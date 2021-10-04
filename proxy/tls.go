package proxy

import (
	"errors"
	"net"
	"strings"
)

type UsedConn struct {
	net.Conn
	usedData []byte
}

func (conn *UsedConn) Read(b []byte) (n int, err error) {
	if conn.usedData != nil {
		n := copy(b, conn.usedData)
		if n < len(conn.usedData) {
			conn.usedData = conn.usedData[n:]
		} else {
			conn.usedData = nil
		}
		return n, nil
	}
	return conn.Conn.Read(b)
}

// https://github.com/fabiolb/fabio/blob/master/proxy/tcp/sni_proxy.go
// IETF RFC: https://datatracker.ietf.org/doc/html/rfc5246
// IBM Doc:  https://www.ibm.com/docs/en/ztpf/2021?topic=sessions-ssl-record-format
//
// ## Format of an SSL handshake record
// Byte   0       = SSL record type = 22 (SSL3_RT_HANDSHAKE)
// Bytes 1-2      = SSL version (major/minor)
// Bytes 3-4      = Length of data in the record (excluding the header itself).
// Byte   5       = Handshake type
// Bytes 6-8      = Length of data to follow in this record
// Bytes 9-n      = Command-specific data
//
// ## for ClientHello record
// Byte     5     = Handshake type
// Bytes   6-8    = Length of data to follow in this record
// Bytes   9-10   = Protocol version
// Bytes  11-42   = Random
// Bytes   43     = SessionID length
// Bytes  44-n    = SessionID
// Bytes n+1-n+2  = CipherSuite length

func checkSNI(conn net.Conn) (c *UsedConn, sni string, err error) {
	c = &UsedConn{conn, nil}

	magicBytes := make([]byte, 9) // pool?
	n, err := conn.Read(magicBytes)
	if n != 0 {
		c.usedData = magicBytes[:n]
	}
	if err != nil {
		return c, "", err
	}

	// tls.recordTypeHandshake == 22
	if len(magicBytes) < 9 || magicBytes[0] != 22 {
		return c, "", errors.New("invalid TLS record type")
	}
	// tls.maxPlaintext == 16384
	recordLength := int(magicBytes[3])<<8 | int(magicBytes[4])
	if recordLength <= 0 || recordLength > 16384 {
		return c, "", errors.New("invalid TLS record length")
	}
	// tls.typeClientHello == 1
	if magicBytes[5] != 1 {
		return c, "", errors.New("invalid client hello type")
	}
	handshakeLength := int(magicBytes[6])<<16 | int(magicBytes[7])<<8 | int(magicBytes[8])
	if handshakeLength <= 0 || handshakeLength > recordLength-4 {
		return c, "", errors.New("invalid client hello length")
	}

	data := make([]byte, handshakeLength) // pool?
	n, err = conn.Read(data)
	if n != 0 {
		c.usedData = append(c.usedData, data[:n]...)
	}
	if err != nil {
		return c, "", err
	}

	sni, err = parseHandshake(data)
	return c, sni, err
}

func parseHandshake(data []byte) (sni string, err error) {
	// recordType(1) + SSLVersion(2) + recordLength(2) + handshakeType(1) + handshakeLength(3) +
	// protocolVersion(2) + random(32) + sessionLength(1)
	// = 9 + 35
	if len(data) < 35 {
		return "", errors.New("invalid client hello message")
	}
	// session_id<0..32>
	sessionLength := int(data[34])
	if sessionLength > 32 || len(data) < 35+sessionLength {
		return "", errors.New("invalid client hello sessionID")
	}

	data = data[35+sessionLength:]
	if len(data) < 2 {
		return "", errors.New("invalid client hello cipher suite")
	}
	// cipher_suites<2..2^16-2>
	cipherSuiteLength := int(data[0])<<8 | int(data[1])
	if cipherSuiteLength%2 != 0 || len(data) < 2+cipherSuiteLength {
		return "", errors.New("invalid client hello cipher suite length")
	}

	data = data[2+cipherSuiteLength:]
	if len(data) < 1 {
		return "", errors.New("invalid client hello compression methods")
	}
	compressionMethodsLength := int(data[0])
	if len(data) < 1+compressionMethodsLength {
		return "", errors.New("invalid client hello compression methods length")
	}

	data = data[1+compressionMethodsLength:]
	// no sni info in extensions
	if len(data) == 0 {
		return "", nil
	}
	if len(data) < 2 {
		return "", errors.New("invalid client hello extensions")
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return "", errors.New("invalid client hello extensions length")
	}

	for len(data) > 0 {
		if len(data) < 4 {
			return "", errors.New("invalid client hello extension")
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		extensionLength := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < extensionLength {
			return "", errors.New("invalid client hello extension length")
		}

		// IETF RFC: https://datatracker.ietf.org/doc/html/rfc6066#section-3
		// tls.extensionServerName == uint16(0)
		if extension == uint16(0) {
			extensionData := data[:extensionLength]
			if len(extensionData) < 2 {
				return "", errors.New("invalid extensionServerName")
			}
			namesLength := int(extensionData[0])<<8 | int(extensionData[1])
			extensionData = extensionData[2:]
			if len(extensionData) != namesLength {
				return "", errors.New("invalid extensionServerName length")
			}
			for len(extensionData) > 0 {
				if len(extensionData) < 3 {
					return "", errors.New("invalid ServerName in extension")
				}
				nameType := extensionData[0]
				nameLength := int(extensionData[1])<<8 | int(extensionData[2])
				extensionData = extensionData[3:]
				if len(extensionData) < nameLength {
					return "", errors.New("invalid ServerName length in extension")
				}
				if nameType == 0 && nameLength > 0 {
					return string(extensionData[:nameLength]), nil
				}
				extensionData = extensionData[nameLength:]
			}
		}
		data = data[extensionLength:]
	}

	return "", nil
}

// localhost => localhost
// example.com => *.example.com + example.com
// a.example.com => *.example.com + example.com
// b.a.example.com => *.a.example.com
func hostPromote(host string) []string {
	arr := strings.Split(host, ".")
	if len(arr) == 1 {
		return []string{host}
	} else if len(arr) == 2 {
		return []string{"*." + host, host}
	} else if len(arr) == 3 {
		return []string{"*." + strings.Join(arr[1:], "."), strings.Join(arr[1:], ".")}
	} else {
		return []string{"*." + strings.Join(arr[1:], ".")}
	}
}

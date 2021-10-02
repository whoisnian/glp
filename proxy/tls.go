package proxy

import (
	"bufio"
	"errors"
	"net"

	"github.com/whoisnian/glb/logger"
)

type TempConn struct {
	net.Conn
	tempData []byte
}

func (conn *TempConn) Read(b []byte) (n int, err error) {
	if len(conn.tempData) > 0 {
		n := copy(b, conn.tempData)
		conn.tempData = nil
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

func checkSNI(conn net.Conn, reader *bufio.Reader) (c *TempConn, sni string, err error) {
	c = &TempConn{conn, nil}

	magicBytes, err := reader.Peek(9)
	if err != nil {
		return c, "", err
	}
	c = &TempConn{conn, magicBytes}

	// tls.recordTypeHandshake == 22
	if len(magicBytes) < 9 || magicBytes[0] != 22 {
		return c, "", errors.New("invalid TLS handshake")
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

	data, err := reader.Peek(9 + handshakeLength)
	if err != nil {
		return c, "", err
	}
	c = &TempConn{conn, data}
	// recordType(1) + SSLVersion(2) + recordLength(2) +
	// handshakeType(1) + handshakeLength(3) + protocolVersion(2) + random(32) + sessionLength(1)
	// = 44
	if len(data) < 44 {
		return c, "", errors.New("invalid client hello message")
	}
	// session_id<0..32>
	sessionLength := int(data[43])
	if sessionLength > 32 || len(data) < 44+sessionLength {
		return c, "", errors.New("invalid client hello sessionID")
	}

	data = data[44+sessionLength:]
	if len(data) < 2 {
		return c, "", errors.New("invalid client hello cipher suite")
	}
	// cipher_suites<2..2^16-2>
	cipherSuiteLength := int(data[0])<<8 | int(data[1])
	if cipherSuiteLength%2 != 0 || len(data) < 2+cipherSuiteLength {
		return c, "", errors.New("invalid client hello cipher suite")
	}

	data = data[2+cipherSuiteLength:]
	if len(data) < 1 {
		return c, "", errors.New("invalid client hello compression methods")
	}
	compressionMethodsLength := int(data[0])
	if len(data) < 1+compressionMethodsLength {
		return c, "", errors.New("invalid client hello compression methods")
	}

	data = data[1+compressionMethodsLength:]
	// no sni info in extensions
	if len(data) == 0 {
		return c, "", nil
	}
	if len(data) < 2 {
		return c, "", errors.New("invalid client hello extensions")
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return c, "", errors.New("invalid client hello extensions")
	}

	for len(data) > 0 {
		if len(data) < 4 {
			return c, "", errors.New("invalid client hello extension")
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		extensionLength := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < extensionLength {
			return c, "", errors.New("invalid client hello extension")
		}

		// IETF RFC: https://datatracker.ietf.org/doc/html/rfc6066#section-3
		// tls.extensionServerName == uint16(0)
		if extension == uint16(0) {
			extensionData := data[:extensionLength]
			if len(extensionData) < 2 {
				return c, "", errors.New("invalid extensionServerName")
			}
			namesLength := int(extensionData[0])<<8 | int(extensionData[1])
			extensionData = extensionData[2:]
			if len(extensionData) != namesLength {
				return c, "", errors.New("invalid extensionServerName")
			}
			for len(extensionData) > 0 {
				if len(extensionData) < 3 {
					return c, "", errors.New("invalid extensionServerName")
				}
				nameType := extensionData[0]
				nameLength := int(extensionData[1])<<8 | int(extensionData[2])
				extensionData = extensionData[3:]
				if len(extensionData) < nameLength {
					return c, "", errors.New("invalid extensionServerName")
				}
				if nameType == 0 && nameLength > 0 {
					return c, string(extensionData[:nameLength]), nil
				}
				extensionData = extensionData[nameLength:]
				logger.Info("extension remain:", len(extensionData))
			}
		}
		data = data[extensionLength:]
		logger.Info("data remain:", len(data))
	}

	return c, "", nil
}

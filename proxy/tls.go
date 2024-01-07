package proxy

import (
	"errors"
)

// https://www.ibm.com/docs/en/ztpf/2023?topic=sessions-ssl-record-format
// https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
// https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/crypto/tls/handshake_messages.go;l=369
//
// SSL handshake record with ClientHello
//
//	Bytes   0       = SSL record type = 0x16 (SSL3_RT_HANDSHAKE)
//	Bytes   1-2     = SSL version (major/minor)
//	Bytes   3-4     = Length of data in the record (excluding the header itself)
//	Bytes   0     +5= Handshake type = 0x01 (SSL3_MT_CLIENT_HELLO)
//	Bytes   1-3   +5= Length of data to follow in this record
//	Bytes   4-5   +5= Protocol version
//	Bytes   6-37  +5= Random
//	Bytes   38-xx +5= SessionID <0..32>
//	Bytes   xx-xx +5= CipherSuites <2..2^16-2>
//	Bytes   xx-xx +5= CompressionMethods <1..2^8-1>
//	Bytes   xx-xx +5= Extensions <8..2^16-1>

const (
	recordHeaderLen        int    = 5
	recordTypeHandshake    uint8  = 0x16
	messageTypeClientHello uint8  = 0x01
	extensionServerName    uint16 = 0
)

func readServerNameIndication(conn *CachedConn) (string, error) {
	hdr, err := conn.Prefetch(recordHeaderLen)
	if err != nil {
		return "", err
	} else if len(hdr) != recordHeaderLen || hdr[0] != recordTypeHandshake {
		return "", errors.New("proxy: invalid TLS record type")
	}

	recordLength := int(hdr[3])<<8 | int(hdr[4])
	if recordLength <= 0 || recordLength > 16384 {
		return "", errors.New("proxy: invalid TLS record length")
	}

	data, err := conn.Prefetch(recordLength)
	if err != nil {
		return "", err
	} else if len(data) != recordLength {
		return "", errors.New("proxy: unexpected TLS record read length")
	}
	return parseHandshakeRecord(data)
}

func parseHandshakeRecord(data []byte) (string, error) {
	if data[0] != messageTypeClientHello {
		return "", errors.New("proxy: invalid TLS client hello message type")
	}
	// skip HandshakeType(1) + HandshakeLength(3) + ProtocolVersion(2) + Random(32)
	data = data[38:]

	// skip SessionID(1+n)
	sessionIdLength := int(data[0])
	data = data[1+sessionIdLength:]

	// skip CipherSuites(2+n)
	cipherSuitesLength := int(data[0])<<8 | int(data[1])
	data = data[2+cipherSuitesLength:]

	// skip CompressionMethods(1+n)
	compressionMethodsLength := int(data[0])
	data = data[1+compressionMethodsLength:]
	if len(data) == 0 {
		return "", nil
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return "", errors.New("proxy: invalid client hello extensions length")
	}
	for len(data) > 0 {
		extType := uint16(data[0])<<8 | uint16(data[1])
		extLength := int(data[2])<<8 | int(data[3])
		extData := data[4 : 4+extLength]

		// https://datatracker.ietf.org/doc/html/rfc6066#section-3
		if extType == extensionServerName {
			extData = extData[2:]
			for len(extData) > 0 {
				nameType := extData[0]
				nameLength := int(extData[1])<<8 | int(extData[2])
				if nameType == 0 && nameLength > 0 {
					return string(extData[3 : 3+nameLength]), nil
				}
				extData = extData[3+nameLength:]
			}
		}
		data = data[4+extLength:]
	}

	return "", nil
}

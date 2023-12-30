package wv

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	wv "github.com/devatadev/gowvserve/wv/proto"
)

type DeviceTypes int64

// DeviceType enum
const (
	ANDROID DeviceTypes = 0
	CHROME  DeviceTypes = 1
)

// Device represents a Widevine device.
type Device struct {
	deviceType *DeviceTypes
	clientID   *wv.ClientIdentification
	cert       *wv.DrmCertificate
	privateKey *rsa.PrivateKey
}

// DeviceSource is a function that returns a Device.
type DeviceSource func() (*Device, error)

// FromRaw creates a Device from raw client ID and private key data.
func FromRaw(clientID, privateKey []byte, deviceType DeviceTypes) DeviceSource {
	return func() (*Device, error) {
		return toDevice(clientID, privateKey, deviceType)
	}
}

// FromWVD creates a Device from a WVD file.
func FromWVD(r io.Reader) DeviceSource {
	return func() (*Device, error) {
		return fromWVD(r)
	}
}

// NewDevice creates a Device from a DeviceSource.
func NewDevice(src DeviceSource) (*Device, error) {
	return src()
}

// ClientID returns the client ID of the device.
func (d *Device) ClientID() *wv.ClientIdentification {
	return d.clientID
}

// DrmCertificate returns the DRM certificate of the device.
func (d *Device) DrmCertificate() *wv.DrmCertificate {
	return d.cert
}

// PrivateKey returns the private key of the device.
func (d *Device) PrivateKey() *rsa.PrivateKey {
	return d.privateKey
}

func (d *Device) Type() *DeviceTypes {
	return d.deviceType
}

type wvHeader struct {
	Signature     [3]byte
	Version       uint8
	Type          uint8
	SecurityLevel uint8
	Flags         byte
}

type wvDataV2 struct {
	PrivateKeyLen uint16
	PrivateKey    []byte
	ClientIDLen   uint16
	ClientID      []byte
}

func fromWVD(r io.Reader) (*Device, error) {
	header := &wvHeader{}
	if err := binary.Read(r, binary.BigEndian, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	if header.Signature != [3]byte{'W', 'V', 'D'} {
		return nil, fmt.Errorf("invalid signature: %v", header.Signature)
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read rest bytes: %w", err)
	}

	switch header.Version {
	case 2:
		data := &wvDataV2{}
		data.PrivateKeyLen = binary.BigEndian.Uint16(rest[:2])
		data.PrivateKey = rest[2 : 2+data.PrivateKeyLen]
		data.ClientIDLen = binary.BigEndian.Uint16(rest[2+data.PrivateKeyLen : 2+data.PrivateKeyLen+2])
		data.ClientID = rest[2+data.PrivateKeyLen+2 : 2+data.PrivateKeyLen+2+data.ClientIDLen]
		deviceType := DeviceTypes(header.Type)
		return toDevice(data.ClientID, data.PrivateKey, deviceType)
	default:
		return nil, fmt.Errorf("unsupported version: %d", header.Version)
	}
}

func toDevice(clientID, privateKey []byte, deviceType DeviceTypes) (*Device, error) {
	c := &wv.ClientIdentification{}
	if err := proto.Unmarshal(clientID, c); err != nil {
		return nil, fmt.Errorf("unmarshal client id: %w", err)
	}

	signedCert := &wv.SignedDrmCertificate{}
	if err := proto.Unmarshal(c.Token, signedCert); err != nil {
		return nil, fmt.Errorf("unmarshal signed cert: %w", err)
	}

	cert := &wv.DrmCertificate{}
	if err := proto.Unmarshal(signedCert.DrmCertificate, cert); err != nil {
		return nil, fmt.Errorf("unmarshal cert: %w", err)
	}

	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &Device{
		deviceType: &deviceType,
		clientID:   c,
		cert:       cert,
		privateKey: key,
	}, nil
}

// parsePrivateKey modified from https://go.dev/src/crypto/tls/tls.go#L339
func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	b := make([]byte, len(data))
	copy(b, data)

	if bytes.HasPrefix(data, []byte("-----")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block containing private key")
		}
		b = block.Bytes
	}

	if key, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", k)
		}
	}

	return nil, fmt.Errorf("unsupported private key type")
}

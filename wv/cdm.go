package wv

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	wv "github.com/devatadev/gowvserve/wv/proto"
	"math/rand"
	"time"

	"google.golang.org/protobuf/proto"
)

var ServiceCertificateRequest = []byte{0x08, 0x04}

const (
	sessionKeyLength = 16
)

// CDM implements the Widevine CDM protocol.
type CDM struct {
	device   *Device
	systemId int
	rand     *rand.Rand
	now      func() time.Time
	session  *[]Session
}

type CDMOption func(*CDM)

func defaultCDMOptions() []CDMOption {
	return []CDMOption{
		WithRandom(rand.NewSource(time.Now().UnixNano())),
		WithNow(time.Now),
		withSystemId(0),
	}
}

func withSystemId(systemId int) CDMOption {
	return func(c *CDM) {
		c.systemId = systemId
	}
}

// WithRandom sets the random source of the CDM.
func WithRandom(source rand.Source) CDMOption {
	return func(c *CDM) {
		c.rand = rand.New(source)
	}
}

// WithNow sets the time now source of the CDM.
func WithNow(now func() time.Time) CDMOption {
	return func(c *CDM) {
		c.now = now
	}
}

// NewCDM creates a new CDM.
//
// Get device by calling NewDevice.
func NewCDM(device *Device, opts ...CDMOption) *CDM {
	if device == nil {
		panic("device cannot be nil")
	}

	c := &CDM{
		device: device,
	}

	for _, opt := range defaultCDMOptions() {
		opt(c)
	}

	for _, opt := range opts {
		opt(c)
	}

	c.session = &[]Session{}

	return c
}

// OpenSession opens a new session.
func (c *CDM) OpenSession() (*Session, error) {
	// if c.session length > 16 then return error
	if len(*c.session) > 16 {
		return nil, fmt.Errorf("too many CDM sessions")
	}
	session := &Session{
		Number: len(*c.session) + 1,
		Id:     c.randomBytes(16),
	}

	*c.session = append(*c.session, *session)

	return session, nil
}

// CloseSession closes a session.
func (c *CDM) CloseSession(sessionId []byte) error {
	for i, s := range *c.session {
		// if session id matches then remove session from slice
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			*c.session = append((*c.session)[:i], (*c.session)[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("session not found")
}

// SetServiceCertificate sets the service certificate of the CDM.
func (c *CDM) SetServiceCertificate(sessionId []byte, cert []byte) (*wv.DrmCertificate, error) {
	for i, s := range *c.session {
		// if session id matches then set service certificate
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			serviceCert, _, err := ParseServiceCert(cert)
			if err != nil {
				return nil, fmt.Errorf("parse service cert: %w", err)
			}
			s.ServiceCertificate = serviceCert
			(*c.session)[i] = s
			return serviceCert, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (c *CDM) GetSystemId() int {
	return c.device.SystemId()
}

// GetServiceCertificate returns the service certificate of the CDM.
func (c *CDM) GetServiceCertificate(sessionId []byte) (*wv.DrmCertificate, error) {
	for _, s := range *c.session {
		// if session id matches then return service certificate
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			return s.ServiceCertificate, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (c *CDM) GetSession(sessionId []byte) (*Session, error) {
	for _, s := range *c.session {
		// if session id matches then return session
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

// GetLicenseChallenge returns the license challenge for the given PSSH.
//
// Set privacyMode to true to enable privacy mode, and you must provide a service certificate.
func (c *CDM) GetLicenseChallenge(sessionId []byte, pssh *PSSH, typ wv.LicenseType, privacyMode bool) ([]byte, error) {
	for i, s := range *c.session {
		// if session id matches then return license challenge
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			if (s.ServiceCertificate == nil || s.ServiceCertificate.PublicKey == nil) && privacyMode {
				return nil, fmt.Errorf("privacy mode must provide cert")
			}
			licenseChallenge, licenseRequest, err := c.getLicenseChallenge(pssh, typ, privacyMode, s.ServiceCertificate)
			if err != nil {
				return nil, fmt.Errorf("get license challenge: %w", err)
			}
			hexSessionId := hex.EncodeToString(s.Id)
			if s.Context == nil {
				s.Context = map[string][][]byte{}
			}
			s.Context[hexSessionId] = [][]byte{licenseChallenge, licenseRequest}
			(*c.session)[i] = s
			return licenseChallenge, err
		}
	}
	return nil, fmt.Errorf("session not found")
}

// GetLicenseChallenge returns the license challenge for the given PSSH.
//
// Set privacyMode to true to enable privacy mode, and you must provide a service certificate.
func (c *CDM) getLicenseChallenge(pssh *PSSH, typ wv.LicenseType, privacyMode bool, serviceCert ...*wv.DrmCertificate) ([]byte, []byte, error) {
	req := &wv.LicenseRequest{
		Type:            wv.LicenseRequest_NEW.Enum(),
		RequestTime:     Pointer(c.now().Unix()),
		ProtocolVersion: wv.ProtocolVersion_VERSION_2_1.Enum(),
		KeyControlNonce: Pointer(c.rand.Uint32()),
		ContentId: &wv.LicenseRequest_ContentIdentification{
			ContentIdVariant: &wv.LicenseRequest_ContentIdentification_WidevinePsshData_{
				WidevinePsshData: &wv.LicenseRequest_ContentIdentification_WidevinePsshData{
					PsshData:    [][]byte{pssh.RawData()},
					LicenseType: typ.Enum(),
					RequestId: []byte(fmt.Sprintf("%08X%08X0100000000000000",
						c.rand.Uint32(),
						c.rand.Uint32())),
				},
			},
		},
	}

	// set client id
	if privacyMode {
		if len(serviceCert) == 0 {
			return nil, nil, fmt.Errorf("privacy mode must provide cert")
		}

		cert := serviceCert[0]
		encClientID, err := c.encryptClientID(cert)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt client id: %w", err)
		}

		req.EncryptedClientId = encClientID
	} else {
		req.ClientId = c.device.ClientID()
	}

	reqData, err := proto.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal license request: %w", err)
	}

	// signed license request signature
	hashed := sha1.Sum(reqData)
	pss, err := rsa.SignPSS(
		rand.New(c.rand),
		c.device.PrivateKey(),
		crypto.SHA1,
		hashed[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, fmt.Errorf("sign pss: %w", err)
	}

	msg := &wv.SignedMessage{
		Type:      wv.SignedMessage_LICENSE_REQUEST.Enum(),
		Msg:       reqData,
		Signature: pss,
	}

	data, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal signed message: %w", err)
	}

	return data, reqData, nil
}

// encryptClientID encrypts the client ID with the service certificate.
//
// The encrypted client ID is used in privacy mode.
func (c *CDM) encryptClientID(cert *wv.DrmCertificate) (*wv.EncryptedClientIdentification, error) {
	privacyKey := c.randomBytes(16)
	privacyIV := c.randomBytes(16)

	block, err := aes.NewCipher(privacyKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	// encryptedClientID
	clientID, err := proto.Marshal(c.device.ClientID())
	if err != nil {
		return nil, fmt.Errorf("marshal client id: %w", err)
	}
	paddedData := Pkcs7Padding(clientID, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, privacyIV)
	encryptedClientID := make([]byte, len(paddedData))
	mode.CryptBlocks(encryptedClientID, paddedData)

	// encryptedPrivacyKey
	publicKey, err := ParsePublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	encryptedPrivacyKey, err := rsa.EncryptOAEP(
		sha1.New(),
		c.rand,
		publicKey,
		privacyKey,
		nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt oaep: %w", err)
	}

	encClientID := &wv.EncryptedClientIdentification{
		ProviderId:                     cert.ProviderId,
		ServiceCertificateSerialNumber: cert.SerialNumber,
		EncryptedClientId:              encryptedClientID,
		EncryptedPrivacyKey:            encryptedPrivacyKey,
		EncryptedClientIdIv:            privacyIV,
	}

	return encClientID, nil
}

func (c *CDM) randomBytes(length int) []byte {
	r := make([]byte, length)
	c.rand.Read(r)
	return r
}

func (c *CDM) ParseLicense(sessionId []byte, license []byte) error {
	for i, s := range *c.session {
		// if session id matches then return license
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			licenseRequest := s.Context[hex.EncodeToString(s.Id)][1]
			if licenseRequest == nil {
				return fmt.Errorf("license request not found")
			}
			keys, err := c.parseLicense(license, licenseRequest)
			if err != nil {
				return fmt.Errorf("parse license: %w", err)
			}
			s.Keys = keys
			(*c.session)[i] = s
			return nil
		}
	}
	return fmt.Errorf("session not found")
}

func (c *CDM) parseLicense(license []byte, licenseRequest []byte) ([]*Key, error) {
	signedMsg := &wv.SignedMessage{}
	if err := proto.Unmarshal(license, signedMsg); err != nil {
		return nil, fmt.Errorf("unmarshal signed message: %w", err)
	}
	if signedMsg.GetType() != wv.SignedMessage_LICENSE {
		return nil, fmt.Errorf("invalid license type: %v", signedMsg.GetType())
	}

	sessionKey, err := c.rsaOAEPDecrypt(c.device.PrivateKey(), signedMsg.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt session key: %w", err)
	}
	if len(sessionKey) != sessionKeyLength {
		return nil, fmt.Errorf("invalid session key length: %v", sessionKey)
	}

	derivedEncKey := deriveEncKey(licenseRequest, sessionKey)
	derivedAuthKey := deriveAuthKey(licenseRequest, sessionKey)

	licenseMsg := &wv.License{}
	if err = proto.Unmarshal(signedMsg.Msg, licenseMsg); err != nil {
		return nil, fmt.Errorf("unmarshal license message: %w", err)
	}

	licenseMsgHMAC := hmac.New(sha256.New, derivedAuthKey)
	licenseMsgHMAC.Write(signedMsg.Msg)
	expectedHMAC := licenseMsgHMAC.Sum(nil)
	if !hmac.Equal(signedMsg.Signature, expectedHMAC) {
		return nil, fmt.Errorf("invalid license signature: %v", signedMsg.Signature)
	}

	keys := make([]*Key, 0)
	for _, key := range licenseMsg.Key {
		decryptedKey, err := DecryptAES(derivedEncKey, key.Iv, key.Key)
		if err != nil {
			return nil, fmt.Errorf("decrypt aes: %w", err)
		}

		keys = append(keys, &Key{
			Type: key.GetType(),
			IV:   key.Iv,
			ID:   key.GetId(),
			Key:  decryptedKey,
		})
	}

	return keys, nil
}

func (c *CDM) GetKeys(sessionId []byte, keyType KeyType) ([]*Key, error) {
	for _, s := range *c.session {
		// if session id matches then return keys
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			if keyType != 0 {
				keys := make([]*Key, 0)
				for _, key := range s.Keys {
					mappedKeyType := KeyType(key.Type)
					if mappedKeyType == keyType {
						keys = append(keys, key)
					}
				}
				return keys, nil
			}
			return s.Keys, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (c *CDM) rsaOAEPDecrypt(privateKey *rsa.PrivateKey, encryptedData []byte) ([]byte, error) {
	decryptedData, err := rsa.DecryptOAEP(sha1.New(), c.rand, privateKey, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

func deriveEncKey(licenseRequest, sessionKey []byte) []byte {
	encKey := make([]byte, 16+len(licenseRequest))

	copy(encKey[:12], "\x01ENCRYPTION\x00")
	copy(encKey[12:], licenseRequest)
	binary.BigEndian.PutUint32(encKey[12+len(licenseRequest):], 128)

	return cmacAES(encKey, sessionKey)
}

func deriveAuthKey(licenseRequest, sessionKey []byte) []byte {
	authKey := make([]byte, 20+len(licenseRequest))

	copy(authKey[:16], "\x01AUTHENTICATION\x00")
	copy(authKey[16:], licenseRequest)
	binary.BigEndian.PutUint32(authKey[16+len(licenseRequest):], 512)

	authCmacKey1 := cmacAES(authKey, sessionKey)
	authKey[0] = 2
	authCmacKey2 := cmacAES(authKey, sessionKey)

	return append(authCmacKey1, authCmacKey2...)
}

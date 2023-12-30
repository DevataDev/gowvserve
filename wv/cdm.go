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
	"fmt"
	wv "github.com/devatadev/gowvserve/wv/proto"
	"math/rand"
	"time"

	"google.golang.org/protobuf/proto"
)

var ServiceCertificateRequest = []byte{0x08, 0x04}

var WidevineSystemID = []byte{0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed}

var CommonPrivacyCert = "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEE" +
	"Qa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3r" +
	"M3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ" +
	"7c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmlu" +
	"ZS5jb20SgAOuNHMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M4PxL/C" +
	"CpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnSq8x2" +
	"/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeF" +
	"Hd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98" +
	"X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ="

var StagingPrivacyCert = "CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhErjQXQI/zF2V4sJRwcZJtBd82NK+7zVbsGdD3mYePSq8" +
	"MYK3mUbVX9wI3+lUB4FemmJ0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKqFxxPZmMNPkxgJxiJf14e+baq9a1Nuip+" +
	"FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7tzY8U1nWpGYD5LKfdxkagatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2fz" +
	"PvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQoJk87wFgRwMzTDY4E5SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUu" +
	"Y29tEoADmD4wNSZ19AunFfwkm9rl1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeEjMdT/0l7ARp9qXeIoA4qprhM19" +
	"ccB6SOv2FgLMpaPzIDCnKVww2pFbkdwYubyVk7jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lexjOY9Dv" +
	"1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s+Cdkxd2b9yfvvpyGH4aTIfat4YkF9Nkvmm2mU224R1hx0WjocL" +
	"sjA89wxul4TJPS3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3Tq26/LfGcF96njtvOUA4P5xRFtICogySKe6W" +
	"nCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8ABHg9bOOTimO0sswHrRWSWX1XF15dXolCk65yEqz5lOfa2/fVomeopkU"

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

func (c *CDM) GetLicenseChallenge(sessionId []byte, pssh *PSSH, typ wv.LicenseType, privacyMode bool) ([]byte, error) {
	for i, s := range *c.session {
		// if session id matches then return license challenge
		if len(s.Id) == len(sessionId) && hmac.Equal(s.Id, sessionId) {
			licenseChallenge, licenseRequest, err := c.getLicenseChallenge(pssh, typ, privacyMode, s.ServiceCertificate)
			if err != nil {
				return nil, fmt.Errorf("get license challenge: %w", err)
			}
			s.LicenseChallenge = licenseChallenge
			s.LicenseChallengeRequest = licenseRequest
			(*c.session)[i] = s
			return s.LicenseChallenge, err
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
			keys, err := c.parseLicense(license, s.LicenseChallengeRequest)
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

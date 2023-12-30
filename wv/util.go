package wv

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"github.com/chmike/cmac-go"
	wv "github.com/devatadev/gowvserve/wv/proto"
	"google.golang.org/protobuf/proto"
	"unsafe"
)

func Pointer[T any](v T) *T {
	return &v
}

func Pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func Pkcs7Unpadding(data []byte, blockSize int) ([]byte, error) {
	paddingLength := int(data[len(data)-1])
	if paddingLength < 1 || paddingLength > blockSize {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLength)
	}

	return data[:len(data)-paddingLength], nil
}

func ParsePublicKey(pubKey []byte) (*rsa.PublicKey, error) {
	publicKey := &rsa.PublicKey{}
	if _, err := asn1.Unmarshal(pubKey, publicKey); err != nil {
		return nil, fmt.Errorf("unmarshal asn1: %w", err)
	}

	return publicKey, nil
}

func cmacAES(data, key []byte) []byte {
	hash, err := cmac.New(aes.NewCipher, key)
	if err != nil {
		return nil
	}

	_, err = hash.Write(data)
	if err != nil {
		return nil
	}

	return hash.Sum(nil)
}

func DecryptAES(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	unpaddedPlaintext, err := Pkcs7Unpadding(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unpaddedPlaintext, nil
}

func GetBytesFromPtr(ptr uintptr, len int, cap int) []byte {
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{ptr, len, cap}
	return *(*[]byte)(unsafe.Pointer(&sl))
}

// ParseServiceCert parses a service certificate which can be used in privacy mode.
func ParseServiceCert(serviceCert []byte) (*wv.DrmCertificate, *wv.SignedDrmCertificate, error) {
	msg := wv.SignedMessage{}
	err := proto.Unmarshal(serviceCert, &msg)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal signed message: %w", err)
	}

	signedCert := &wv.SignedDrmCertificate{}
	if err = proto.Unmarshal(msg.Msg, signedCert); err != nil {
		return nil, nil, fmt.Errorf("unmarshal signed drm certificate: %w", err)
	}

	cert := &wv.DrmCertificate{}
	if err = proto.Unmarshal(signedCert.DrmCertificate, cert); err != nil {
		return nil, nil, fmt.Errorf("unmarshal drm certificate: %w", err)
	}

	return cert, signedCert, nil
}

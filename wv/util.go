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
)

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

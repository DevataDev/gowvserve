package wv

import wv "github.com/devatadev/gowvserve/wv/proto"

type Session struct {
	Number             int
	Id                 []byte
	ServiceCertificate *wv.DrmCertificate
	LicenseChallenge   []byte
	Keys               []*Key
}

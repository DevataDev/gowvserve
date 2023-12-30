package wv

import wv "github.com/devatadev/gowvserve/wv/proto"

type Session struct {
	Number                  int
	Id                      []byte
	LicenseChallenge        []byte
	LicenseChallengeRequest []byte
	ServiceCertificate      *wv.DrmCertificate
	Keys                    []*Key
}

package wv

import (
	"encoding/hex"
	wv "github.com/devatadev/gowvserve/wv/proto"
)

type Session struct {
	Number             int
	Id                 []byte
	Context            map[string][][]byte
	ServiceCertificate *wv.DrmCertificate
	Keys               []*Key
}

func (s *Session) HexId() string {
	return hex.EncodeToString(s.Id)
}

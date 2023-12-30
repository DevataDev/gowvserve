package wv

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/Eyevinn/mp4ff/mp4"
	wv "github.com/devatadev/gowvserve/wv/proto"
	"google.golang.org/protobuf/proto"
)

var WidevineSystemID = []byte{0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed}

// WidevineSystemID is the system ID of Widevine.
// PSSH represents a PSSH box containing Widevine data.
type PSSH struct {
	box  *mp4.PsshBox
	data *wv.WidevinePsshData
}

// NewPSSH creates a PSSH from bytes
func NewPSSH(b []byte) (*PSSH, error) {
	box, err := mp4.DecodeBox(0, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("decode box: %w", err)
	}

	psshBox, ok := box.(*mp4.PsshBox)
	if !ok {
		return nil, fmt.Errorf("box is a %s instead of a PSSH", box.Type())
	}

	wvSystemIdStr := hex.EncodeToString(WidevineSystemID)

	if hex.EncodeToString(psshBox.SystemID) != wvSystemIdStr {
		return nil, fmt.Errorf("system id is %s instead of widevine", hex.EncodeToString(psshBox.SystemID))
	}

	data := &wv.WidevinePsshData{}
	if err = proto.Unmarshal(psshBox.Data, data); err != nil {
		return nil, fmt.Errorf("unmarshal pssh data: %w", err)
	}

	return &PSSH{
		box:  psshBox,
		data: data,
	}, nil
}

// Version returns the version of the PSSH box.
func (p *PSSH) Version() byte {
	return p.box.Version
}

// Flags returns the flags of the PSSH box.
func (p *PSSH) Flags() uint32 {
	return p.box.Flags
}

// RawData returns the data of the PSSH box.
func (p *PSSH) RawData() []byte {
	return p.box.Data
}

// Data returns the parsed data of the PSSH box.
func (p *PSSH) Data() *wv.WidevinePsshData {
	return p.data
}

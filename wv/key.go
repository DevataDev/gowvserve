package wv

import wv "github.com/devatadev/gowvserve/wv/proto"

type KeyType int64

const (
	SIGNING          KeyType = 1 // Exactly one key of this type must appear.
	CONTENT          KeyType = 2 // Content key.
	KEY_CONTROL      KeyType = 3 // Key control block for license renewals. No key.
	OPERATOR_SESSION KeyType = 4 // wrapped keys for auxiliary crypto operations.
	ENTITLEMENT      KeyType = 5 // Entitlement keys.
	OEM_CONTENT      KeyType = 6
)

type Key struct {
	// Type is the type of key.
	Type wv.License_KeyContainer_KeyType
	// IV is the initialization vector of the key.
	IV []byte
	// ID is the ID of the key.
	ID []byte
	// Key is the key.
	Key []byte
}

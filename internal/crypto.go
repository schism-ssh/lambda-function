package internal

import (
	"crypto/ed25519"
	"encoding/pem"
	"github.com/mikesmitty/edkey"
)

func CreateCA() []byte {
	_, privKey, _ := ed25519.GenerateKey(nil)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	return pem.EncodeToMemory(pemKey)
}

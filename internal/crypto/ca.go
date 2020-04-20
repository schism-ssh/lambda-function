package crypto

import (
	"crypto/ed25519"
	"encoding/pem"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
)

const CAPrivKeyType = "OPENSSH PRIVATE KEY"

type CaSshKeyPair struct {
	PrivateKey    []byte `json:"private_key"`
	AuthorizedKey []byte `json:"authorized_key"`
}

func CreateCA() (*CaSshKeyPair, error) {
	rawPubKey, rawPrivKey, _ := ed25519.GenerateKey(nil)

	publicKey, err := ssh.NewPublicKey(rawPubKey)
	if err != nil {
		return nil, err
	}

	pemKey := &pem.Block{
		Type:  CAPrivKeyType,
		Bytes: edkey.MarshalED25519PrivateKey(rawPrivKey),
	}

	privateKey := pem.EncodeToMemory(pemKey)
	publicAuthorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	return &CaSshKeyPair{
		PrivateKey:    privateKey,
		AuthorizedKey: publicAuthorizedKey,
	}, nil
}

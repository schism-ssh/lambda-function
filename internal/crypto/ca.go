package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
)

const CAPrivKeyType = "PRIVATE KEY"

type EncodedCaPair struct {
	PrivateKey    []byte `json:"private_key"`
	AuthorizedKey []byte `json:"authorized_key"`
}

func (encoded *EncodedCaPair) Signer() (ssh.Signer, error) {
	rawPrivKey, err := ssh.ParsePrivateKey(encoded.PrivateKey)
	if err != nil {
		return nil, err
	}
	return rawPrivKey, nil
}

func CreateCA() (*EncodedCaPair, error) {
	rawPubKey, rawPrivKey, _ := ed25519.GenerateKey(nil)
	rawPemBytes, err := x509.MarshalPKCS8PrivateKey(rawPrivKey)
	if err != nil {
		return nil, err
	}
	pemKey := &pem.Block{
		Type:  CAPrivKeyType,
		Bytes: rawPemBytes,
	}

	publicKey, _ := ssh.NewPublicKey(rawPubKey)
	return &EncodedCaPair{
		PrivateKey:    pem.EncodeToMemory(pemKey),
		AuthorizedKey: ssh.MarshalAuthorizedKey(publicKey),
	}, nil
}

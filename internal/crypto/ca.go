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
	Fingerprint   string `json:"fingerprint"`
}

func (encoded *EncodedCaPair) Signer() (ssh.Signer, error) {
	rawPrivKey, err := ssh.ParsePrivateKey(encoded.PrivateKey)
	if err != nil {
		return nil, err
	}
	return rawPrivKey, nil
}

func CreateCA() *EncodedCaPair {
	rawPubKey, rawPrivKey, _ := ed25519.GenerateKey(nil)
	rawPemBytes, _ := x509.MarshalPKCS8PrivateKey(rawPrivKey)
	pemKey := &pem.Block{
		Type:  CAPrivKeyType,
		Bytes: rawPemBytes,
	}

	publicKey, _ := ssh.NewPublicKey(rawPubKey)
	return &EncodedCaPair{
		PrivateKey:    pem.EncodeToMemory(pemKey),
		AuthorizedKey: ssh.MarshalAuthorizedKey(publicKey),
		Fingerprint:   ssh.FingerprintSHA256(publicKey),
	}
}

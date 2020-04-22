package crypto

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"math/rand"
)

const (
	CAPrivKeyType = "OPENSSH PRIVATE KEY"
	OpenSSHMagic  = "openssh-key-v1"
)

type CaSshKeyPair struct {
	PrivateKey    []byte `json:"private_key"`
	AuthorizedKey []byte `json:"authorized_key"`
}

type privKeyEncoding struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type privateKeyBlock struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Pub     []byte
	Priv    []byte
	Comment string
	Pad     []byte `ssh:"rest"`
}

func marshalED25519PrivateKey(key ed25519.PrivateKey, comment string) []byte {
	/* Add the key header followed by a null byte */
	magic := append([]byte(OpenSSHMagic), 0)

	ci := rand.Uint32()
	pubKey, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		// This shouldn't ever happen? But someone thinks it can...
		return nil
	}
	pk1 := privateKeyBlock{
		Check1:  ci,
		Check2:  ci,
		Keytype: ssh.KeyAlgoED25519,
		Pub:     pubKey,
		Priv:    key,
		Comment: comment,
	}

	/* Add in padding to the internal block */
	blockSize := 8
	blockLen := len(ssh.Marshal(pk1))
	// 0 <= padLen < blockSize
	padLen := (blockSize - (blockLen % blockSize)) % blockSize
	pk1.Pad = make([]byte, padLen)
	// Padding is a sequence of bytes like 1, 2, 3...
	for i := 0; i < padLen; i++ {
		pk1.Pad[i] = byte(i + 1)
	}

	/* Generate the pubkey prefix "\0\0\0\nssh-ed25519\0\0\0 " */
	prefix := []byte{0x0, 0x0, 0x0, 0x0b}
	prefix = append(prefix, []byte(pk1.Keytype)...)
	prefix = append(prefix, []byte{0x0, 0x0, 0x0, 0x20}...)

	encoding := privKeyEncoding{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      1,
		PubKey:       append(prefix, pubKey...),
		PrivKeyBlock: ssh.Marshal(pk1),
	}
	return append(magic, ssh.Marshal(encoding)...)
}

func formatAuthorizedKey(publicKey ssh.PublicKey, keyComment string) []byte {
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)
	publicComment := fmt.Sprintf(" %s\n", keyComment)
	authorizedKey = append(authorizedKey[:len(authorizedKey)-1], []byte(publicComment)...)
	return authorizedKey
}

func CreateCA(keyType string) (*CaSshKeyPair, error) {
	keyComment := fmt.Sprintf("CA Key for siging %s certificates", keyType)
	rawPubKey, rawPrivKey, _ := ed25519.GenerateKey(nil)
	publicKey, err := ssh.NewPublicKey(rawPubKey)
	if err != nil {
		return nil, err
	}

	pemKey := &pem.Block{
		Type:  CAPrivKeyType,
		Bytes: marshalED25519PrivateKey(rawPrivKey, keyComment),
	}

	return &CaSshKeyPair{
		PrivateKey:    pem.EncodeToMemory(pemKey),
		AuthorizedKey: formatAuthorizedKey(publicKey, keyComment),
	}, nil
}

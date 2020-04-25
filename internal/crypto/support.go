package crypto

import "golang.org/x/crypto/ssh"

func LazyParseAuthorizedKey(authKey []byte) (ssh.PublicKey, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(authKey)
	return pubKey, err
}

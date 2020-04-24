package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/ssh"
	"time"
)

type SigningReq struct {
	PublicKey  []byte
	CertType   uint32
	Identity   string
	Principals []string
	TTL        int64
}

var oneMinAgo = uint64(time.Now().Unix() - 60)

func certSerial() uint64 {
	buff := make([]byte, 8)
	_, _ = rand.Read(buff)
	return binary.LittleEndian.Uint64(buff)
}

func Sign(req *SigningReq, caKey ssh.Signer) (*ssh.Certificate, error) {
	certExpiresAt := uint64(time.Now().Unix() + req.TTL)
	pubKey, err := LazyParseAuthorizedKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Serial:          certSerial(),
		Key:             pubKey,
		KeyId:           req.Identity,
		ValidPrincipals: req.Principals,
		ValidAfter:      oneMinAgo,
		ValidBefore:     certExpiresAt,
		CertType:        req.CertType,
		Permissions: ssh.Permissions{
			CriticalOptions: nil,
			Extensions:      nil,
		},
	}

	err = cert.SignCert(rand.Reader, caKey)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func MarshalSignedCert(signedCert *ssh.Certificate) []byte {
	marshaled := ssh.MarshalAuthorizedKey(signedCert)
	return append(marshaled[:len(marshaled)-1], []byte(signedCert.KeyId)...)
}

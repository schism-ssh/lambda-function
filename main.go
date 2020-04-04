package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
	"log"
)

var invokeCount = 0

func LambdaHandler() (int, error) {
	invokeCount = invokeCount + 1

	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	publicKey, _ := ssh.NewPublicKey(pubKey)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	privateKey := pem.EncodeToMemory(pemKey)
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)
	log.Print(string(privateKey))
	log.Print(string(authorizedKey))
	return invokeCount, nil
}

func main() {
	lambda.Start(LambdaHandler)
}

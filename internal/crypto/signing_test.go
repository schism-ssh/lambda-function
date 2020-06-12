package crypto_test

import (
	"golang.org/x/crypto/ssh"
	"src.doom.fm/schism/lambda-function/internal/crypto"
	"strings"
	"testing"
)

var testSigner, _ = crypto.CreateCA().Signer()

func TestMarshalSignedCert(t *testing.T) {
	var testReq = &crypto.SigningReq{
		PublicKey:  crypto.HelperLoadBytes(t, "ed25519-key.pub"),
		CertType:   ssh.HostCert,
		Identity:   "test.example.com",
		Principals: []string{"test.example.com"},
		TTL:        300,
	}
	var testSignedCert, _ = crypto.Sign(testReq, testSigner)

	type args struct {
		signedCert *ssh.Certificate
	}
	tests := []struct {
		name         string
		args         args
		wantContains string
	}{
		{
			name:         "marshaled cert contains comment with the identity",
			args:         args{signedCert: testSignedCert},
			wantContains: testReq.Identity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crypto.MarshalSignedCert(tt.args.signedCert); !strings.Contains(string(got), tt.wantContains) {
				t.Errorf("MarshalSignedCert() = '%s', wantContains '%v'", got, tt.wantContains)
			}
		})
	}
}

func TestSign(t *testing.T) {
	var testReq = &crypto.SigningReq{
		PublicKey:  crypto.HelperLoadBytes(t, "ed25519-key.pub"),
		CertType:   ssh.HostCert,
		Identity:   "test.example.com",
		Principals: []string{"test.example.com"},
		TTL:        300,
	}
	type args struct {
		req   *crypto.SigningReq
		caKey ssh.Signer
	}
	tests := []struct {
		name          string
		args          args
		wantSignature bool
		wantErr       bool
	}{
		{
			name: "produces a valid signed certificate",
			args: args{
				req:   testReq,
				caKey: testSigner,
			},
			wantSignature: true,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := crypto.Sign(tt.args.req, tt.args.caKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Error("got was nil but no err returned? wtf")
				return
			}
			gotSignature := got.Signature != nil
			if gotSignature != tt.wantSignature {
				t.Errorf("Sign() got.Signature present: %t, wanted Signature?: %t", gotSignature, tt.wantSignature)
			}
		})
	}
}

package crypto_test

import (
	"golang.org/x/crypto/ssh"
	"src.doom.fm/schism/lambda-function/internal/crypto"
	"testing"
)

func TestLazyParseAuthorizedKey(t *testing.T) {
	var testAuthKey = crypto.HelperLoadBytes(t, "ed25519-key.pub")
	type args struct {
		authKey []byte
	}
	tests := []struct {
		name        string
		args        args
		wantKeyType string
		wantErr     bool
	}{
		{
			name: "Returns error if key is malformed",
			args: args{
				authKey: []byte("not-a-valid-authorized-key"),
			},
			wantKeyType: "",
			wantErr:     true,
		},
		{
			name: "returns a valid public key for a valid auth key",
			args: args{
				authKey: testAuthKey,
			},
			wantKeyType: ssh.KeyAlgoED25519,
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := crypto.LazyParseAuthorizedKey(tt.args.authKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("LazyParseAuthorizedKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(tt.wantKeyType) > 0 && got != nil && got.Type() != tt.wantKeyType {
				t.Errorf("LazyParseAuthorizedKey() got = '%v', wantKeyType = '%v'", got.Type(), tt.wantKeyType)
			}
		})
	}
}

package crypto

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"reflect"
	"strings"
	"testing"
)

func TestCreateCA(t *testing.T) {
	tests := []struct {
		name    string
		want    *EncodedCaPair
	}{
		{
			name:    "privateKey encoded PEM type PRIVATE KEY",
			want:    &EncodedCaPair{PrivateKey: []byte("-BEGIN PRIVATE KEY-")},
		},
		{
			name:    fmt.Sprintf("authorizedKey is of type %s", ssh.KeyAlgoED25519),
			want:    &EncodedCaPair{AuthorizedKey: []byte(ssh.KeyAlgoED25519)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateCA()
			if got == nil {
				t.Errorf("CreateCA() = %v, wanted not nil", got)
				return
			}
			if tt.want.PrivateKey != nil &&
				!strings.Contains(string(got.PrivateKey), string(tt.want.PrivateKey)) {
				t.Errorf(
					"CreateCA().PrivateKey = %v, wanted it to contain %v",
					got.PrivateKey, tt.want.PrivateKey,
				)
			}
			if tt.want.AuthorizedKey != nil &&
				!strings.Contains(string(got.AuthorizedKey), string(tt.want.AuthorizedKey)) {
				t.Errorf(
					"CreateCA().AuthorizedKey = %v, wanted it to contain %v",
					string(got.AuthorizedKey), string(tt.want.AuthorizedKey),
				)
			}
		})
	}
}

func TestEncodedCaPair_Signer(t *testing.T) {
	type fields struct {
		PrivateKey    []byte
		AuthorizedKey []byte
		Fingerprint   string
	}
	tests := []struct {
		name    string
		fields  fields
		want    ssh.Signer
		wantErr bool
	}{
		{
			name:    "Get Signer() to fail with an empty CaPair Object",
			fields:  fields{},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := &EncodedCaPair{
				PrivateKey:    tt.fields.PrivateKey,
				AuthorizedKey: tt.fields.AuthorizedKey,
				Fingerprint:   tt.fields.Fingerprint,
			}
			got, err := encoded.Signer()
			if (err != nil) != tt.wantErr {
				t.Errorf("Signer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer() got = %v, want %v", got, tt.want)
			}
		})
	}
}

package crypto

import (
	"strings"
	"testing"
)

func TestCreateCA(t *testing.T) {
	tests := []struct {
		name    string
		want    *CaSshKeyPair
		wantErr bool
	}{
		{
			name:    "privateKey contains 'OPENSSH PRIVATE KEY'",
			want:    &CaSshKeyPair{PrivateKey: []byte("OPENSSH PRIVATE KEY")},
			wantErr: false,
		},
		{
			name:    "authorizedKey is not empty",
			want:    &CaSshKeyPair{AuthorizedKey: []byte("ssh-ed25519")},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCA()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("CreateCA() = %v, wanted not nil", got)
				return
			}
			if tt.want.PrivateKey != nil &&
				got != nil &&
				!strings.Contains(string(got.PrivateKey), string(tt.want.PrivateKey)) {
				t.Errorf(
					"CreateCA().PrivateKey = %v, wanted it to contain %v",
					got.PrivateKey, tt.want.PrivateKey,
				)
			}
			if tt.want.AuthorizedKey != nil &&
				got != nil &&
				!strings.Contains(string(got.AuthorizedKey), string(tt.want.AuthorizedKey)) {
				t.Errorf(
					"CreateCA().AuthorizedKey = %v, wanted it to contain %v",
					string(got.AuthorizedKey), string(tt.want.AuthorizedKey),
				)
			}
		})
	}
}

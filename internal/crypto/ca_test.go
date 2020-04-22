package crypto

import (
	"strings"
	"testing"

	"src.doom.fm/schism/commonLib/protocol"
)

func TestCreateCA(t *testing.T) {
	type args struct {
		keyType string
	}
	tests := []struct {
		name    string
		args    args
		want    *CaSshKeyPair
		wantErr bool
	}{
		{
			name:    "privateKey contains 'OPENSSH PRIVATE KEY'",
			args:    args{keyType: protocol.HostCertificate},
			want:    &CaSshKeyPair{PrivateKey: []byte("OPENSSH PRIVATE KEY")},
			wantErr: false,
		},
		{
			name:    "authorizedKey contains comment matching the keyType",
			args:    args{keyType: protocol.UserCertificate},
			want:    &CaSshKeyPair{AuthorizedKey: []byte(protocol.UserCertificate + " certificates")},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCA(tt.args.keyType)
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

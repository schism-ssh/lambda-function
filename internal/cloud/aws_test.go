package cloud

import (
	"errors"
	"reflect"
	"src.doom.fm/schism/lambda-function/internal/crypto"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

type mockSSMClient struct {
	ssmiface.SSMAPI
}

func (m *mockSSMClient) PutParameter(input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
	resp := &ssm.PutParameterOutput{}
	return resp, nil
}
func (m *mockSSMClient) GetParameter(input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
	resp := &ssm.GetParameterOutput{
		Parameter: &ssm.Parameter{
			Name:  aws.String("valid-param-name"),
			Value: aws.String("{\"private_key\":null,\"authorized_key\":null}"),
		},
	}
	if *input.Name == "valid-param-name" {
		return resp, nil
	} else {
		return nil, errors.New("InvalidKeyId")
	}
}

func TestSaveCAToSSM(t *testing.T) {
	type args struct {
		ssmSvc      ssmiface.SSMAPI
		caPair      *crypto.CaSshKeyPair
		caParamName string
		ssmKmsKeyId string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No KMS Key provided",
			args: args{
				ssmSvc: &mockSSMClient{},
				caPair: &crypto.CaSshKeyPair{
					PrivateKey:    nil,
					AuthorizedKey: nil,
				},
				caParamName: "schism-ca-key-host",
				ssmKmsKeyId: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveCAToSSM(tt.args.ssmSvc, tt.args.caPair, tt.args.caParamName, tt.args.ssmKmsKeyId); (err != nil) != tt.wantErr {
				t.Errorf("SaveCAToSSM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadCAFromSSM(t *testing.T) {
	type args struct {
		ssmSvc    ssmiface.SSMAPI
		paramName string
	}
	tests := []struct {
		name    string
		args    args
		want    *crypto.CaSshKeyPair
		wantErr bool
	}{
		{
			name: "key exists",
			args: args{
				ssmSvc:    &mockSSMClient{},
				paramName: "valid-param-name",
			},
			want:    &crypto.CaSshKeyPair{},
			wantErr: false,
		},
		{
			name: "key is missing",
			args: args{
				ssmSvc:    &mockSSMClient{},
				paramName: "non-existent-param",
			},
			want: nil, wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadCAFromSSM(tt.args.ssmSvc, tt.args.paramName)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadCAFromSSM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadCAFromSSM() got = %v, want %v", got, tt.want)
			}
		})
	}
}
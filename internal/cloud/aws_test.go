package cloud

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"

	"src.doom.fm/schism/commonLib/protocol"
	"src.doom.fm/schism/lambda-function/internal/crypto"
)

type mockSSMClient struct {
	ssmiface.SSMAPI
	ssmKmsKeyId string
}

func (m *mockSSMClient) PutParameter(input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
	if strings.Contains(*input.Name, "schism-ca-key") {
		if len(m.ssmKmsKeyId) >= 1 && len(*input.KeyId) < 1 {
			return nil, fmt.Errorf("error with kms key: %s, wanted: %s", *input.KeyId, m.ssmKmsKeyId)
		}
		resp := &ssm.PutParameterOutput{}
		return resp, nil
	} else {
		return nil, fmt.Errorf("error saving parameter: %v", *input.Name)
	}
}
func (m *mockSSMClient) GetParameter(input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
	resp := &ssm.GetParameterOutput{
		Parameter: &ssm.Parameter{
			Name:  aws.String("valid-param-name"),
			Value: aws.String(`{"private_key":null,"authorized_key":null}`),
		},
	}
	brokenResp := &ssm.GetParameterOutput{
		Parameter: &ssm.Parameter{
			Name:  aws.String("broken-param"),
			Value: aws.String(`{"private_key": "IsThisValidBase64?"}`),
		},
	}
	switch *input.Name {
	case "valid-param-name":
		return resp, nil
	case "broken-param":
		return brokenResp, nil
	default:
		return nil, errors.New("InvalidKeyId")
	}
}

type mockS3Client struct {
	s3iface.S3API
}

func (m *mockS3Client) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	if strings.Contains(*input.Key, "fail:") {
		return nil, fmt.Errorf("error saving object: %v", *input.Key)
	}
	return &s3.PutObjectOutput{}, nil
}

func TestSaveCAToSSM(t *testing.T) {
	type args struct {
		ssmSvc      ssmiface.SSMAPI
		caPair      *crypto.EncodedCaPair
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
				ssmSvc:      &mockSSMClient{},
				caPair:      &crypto.EncodedCaPair{},
				caParamName: "schism-ca-key-host",
				ssmKmsKeyId: "",
			},
			wantErr: false,
		},
		{
			name: "KMS Key Provided",
			args: args{
				ssmSvc:      &mockSSMClient{ssmKmsKeyId: "test-kms-key-id"},
				caPair:      &crypto.EncodedCaPair{},
				caParamName: "schism-ca-key-user",
				ssmKmsKeyId: "test-kms-key-id",
			},
		},
		{
			name: "Error saving to SSM",
			args: args{
				ssmSvc:      &mockSSMClient{},
				caPair:      &crypto.EncodedCaPair{},
				caParamName: "this-fails-to-save",
				ssmKmsKeyId: "",
			},
			wantErr: true,
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
		want    *crypto.EncodedCaPair
		wantErr bool
	}{
		{
			name: "key exists",
			args: args{
				ssmSvc:    &mockSSMClient{},
				paramName: "valid-param-name",
			},
			want:    &crypto.EncodedCaPair{},
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
		{
			name: "stored key is corrupt",
			args: args{
				ssmSvc:    &mockSSMClient{},
				paramName: "broken-param",
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

func TestSaveS3Object(t *testing.T) {
	type args struct {
		s3Svc    s3iface.S3API
		config   SchismConfig
		s3Object protocol.S3Object
	}
	s3Bucket := "schism-test"
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Saving User Signed Certificate",
			args: args{
				s3Svc: &mockS3Client{}, config: SchismConfig{
					CertsS3Bucket: s3Bucket,
					CertsS3Prefix: "test/",
				},
				s3Object: &protocol.SignedCertificateS3Object{
					CertificateType: protocol.UserCertificate,
					Identity:        "user@test.schism.example.com",
					Principals:      []string{"user1", "app_user"},
				},
			},
			want:    "test/user:1d2206f7294dedac0c991bbf3656db48a7e93cc913c7e467c4c9d2d6149ab83c.json",
			wantErr: false,
		},
		{
			name: "Saving Host CA Certificate",
			args: args{
				s3Svc: &mockS3Client{}, config: SchismConfig{CertsS3Bucket: s3Bucket},
				s3Object: &protocol.CAPublicKeyS3Object{CertificateType: protocol.HostCertificate},
			},
			want: "CA-Pubkeys/host.json", wantErr: false,
		},
		{
			name: "Saving fails",
			args: args{
				s3Svc: &mockS3Client{}, config: SchismConfig{CertsS3Bucket: s3Bucket},
				s3Object: &protocol.SignedCertificateS3Object{CertificateType: "fail"},
			},
			want: "", wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SaveS3Object(tt.args.s3Svc, tt.args.config, tt.args.s3Object)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveS3Object() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SaveS3Object() got = %v, want %v", got, tt.want)
			}
		})
	}
}

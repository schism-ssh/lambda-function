package cloud

import (
	"errors"
	"reflect"
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

type mockS3Client struct {
	s3iface.S3API
}

func (m *mockS3Client) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
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
				ssmSvc: &mockSSMClient{},
				caPair: &crypto.EncodedCaPair{
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

func TestSaveCertToS3(t *testing.T) {
	type args struct {
		s3Svc    s3iface.S3API
		s3Bucket string
		s3Object *protocol.SignedCertificateS3Object
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "save host cert",
			args: args{
				s3Svc: &mockS3Client{}, s3Bucket: "schism-test",
				s3Object: &protocol.SignedCertificateS3Object{
					CertificateType: "host",
					Identity:        "test.schism.example.com",
					Principals:      []string{"test.schism.example.com"},
				},
			},
			want:    "hosts/73f386e91cac74186f60ba0aca0a410c234b3cfafb68f20541e4c5a828a1491b.json",
			wantErr: false,
		},
		{
			name: "save user cert",
			args: args{
				s3Svc: &mockS3Client{}, s3Bucket: "schism-test",
				s3Object: &protocol.SignedCertificateS3Object{
					CertificateType: "user",
					Identity:        "user@test.schism.example.com",
					Principals:      []string{"user1", "app_user"},
				},
			},
			want:    "users/1d2206f7294dedac0c991bbf3656db48a7e93cc913c7e467c4c9d2d6149ab83c.json",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SaveCertToS3(tt.args.s3Svc, tt.args.s3Bucket, tt.args.s3Object)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveCertToS3() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SaveCertToS3() got = %v, want %v", got, tt.want)
			}
		})
	}
}

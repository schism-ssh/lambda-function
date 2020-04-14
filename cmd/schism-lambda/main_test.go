package main

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"reflect"
	"strings"
	"testing"
)

type mockSSMClient struct {
	ssmiface.SSMAPI
	GetResp *ssm.GetParameterOutput
	PutResp *ssm.PutParameterOutput
}

func (m *mockSSMClient) PutParameter(input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
	if ssmKmsKeyId == "" && input.KeyId != nil {
		return nil, errors.New("missing KeyId")
	}
	return m.PutResp, nil
}
func (m *mockSSMClient) GetParameter(input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
	return m.GetResp, nil
}

func Test_caParamName(t *testing.T) {
	type args struct {
		caType string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{ // User CA Key
			name: "user ca key name",
			args: args{
				caType: "user",
			},
			want: "schism-user-ca-key",
		},
		{
			name: "host ca key name",
			args: args{
				caType: "host",
			},
			want: "schism-host-ca-key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := caParamName(tt.args.caType); got != tt.want {
				t.Errorf("caParamName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createCA(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "returned []byte is not empty",
			want: "",
		},
		{
			name: "returned []byte contains 'OPENSSH PRIVATE KEY'",
			want: "OPENSSH PRIVATE KEY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createCA()
			if len(tt.want) < 1 {
				if len(got) < 1 {
					t.Errorf("createCA() = %v, wanted not an empty array", got)
				}
			} else {
				if !strings.Contains(string(got), tt.want) {
					t.Errorf("createCA() = %v, wanted it to contain %v", string(got), tt.want)
				}
			}
		})
	}
}

func Test_loadCAFromSSM(t *testing.T) {
	type args struct {
		ssmSvc    ssmiface.SSMAPI
		paramName string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "basic load from ssm",
			args: args{
				ssmSvc: &mockSSMClient{
					GetResp: &ssm.GetParameterOutput{
						Parameter: &ssm.Parameter{
							Value: aws.String("test"),
						}},
				},
				paramName: "unimportant",
			},
			want: []byte("test"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loadCAFromSSM(tt.args.ssmSvc, tt.args.paramName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadCAFromSSM() = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func Test_saveCAToSSM(t *testing.T) {
	type args struct {
		ssmSvc      ssmiface.SSMAPI
		caContents  []byte
		caParamName string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no kms key provided",
			args: args{
				ssmSvc: &mockSSMClient{
					PutResp: &ssm.PutParameterOutput{},
				},
				caContents:  make([]byte, 1),
				caParamName: "schism-test-key",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveCAToSSM(tt.args.ssmSvc, tt.args.caContents, tt.args.caParamName)
		})
	}
}

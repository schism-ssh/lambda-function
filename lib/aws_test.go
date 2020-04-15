package lib

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"reflect"
	"testing"
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
			Value: aws.String("test-value"),
		},
	}
	if *input.Name == "valid-param-name" {
		return resp, nil
	} else {
		return nil, errors.New("InvalidKeyId")
	}
}

func TestLoadCAsFromSSM(t *testing.T) {
	type args struct {
		ssmSvc ssmiface.SSMAPI
		params *CaParamNames
	}
	tests := []struct {
		name     string
		args     args
		wantHost []byte
		wantUser []byte
		wantErrs []bool
	}{
		{
			name: "both params exist in ssm",
			args: args{
				ssmSvc: &mockSSMClient{},
				params: &CaParamNames{Host: "valid-param-name", User: "valid-param-name"},
			},
			wantHost: []byte("test-value"), wantUser: []byte("test-value"), wantErrs: []bool{false, false},
		},
		{
			name:     "host ca param is missing",
			args:     args{ssmSvc: &mockSSMClient{}, params: &CaParamNames{Host: "missing", User: "valid-param-name"}},
			wantHost: nil, wantUser: []byte("test-value"), wantErrs: []bool{true, false},
		},
		{
			name:     "user ca param is missing",
			args:     args{ssmSvc: &mockSSMClient{}, params: &CaParamNames{Host: "valid-param-name", User: "missing"}},
			wantHost: []byte("test-value"), wantUser: nil, wantErrs: []bool{false, true},
		},
		{
			name:     "both ca params are missing",
			args:     args{ssmSvc: &mockSSMClient{}, params: &CaParamNames{Host: "missing", User: "missing"}},
			wantHost: nil, wantUser: nil, wantErrs: []bool{true, true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotUser, gotErrs := LoadCAsFromSSM(tt.args.ssmSvc, tt.args.params)
			if !reflect.DeepEqual(gotHost, tt.wantHost) {
				t.Errorf("LoadCAsFromSSM() gotHost = %v, want %v", gotHost, tt.wantHost)
			}
			if !reflect.DeepEqual(gotUser, tt.wantUser) {
				t.Errorf("LoadCAsFromSSM() gotUser = %v, want %v", gotUser, tt.wantUser)
			}
			if tt.wantErrs[0] != (gotErrs[0] != nil) && tt.wantErrs[1] != (gotErrs[1] != nil) {
				t.Errorf("LoadCAsFromSSM() gotErrs = %v, want %v", gotErrs, tt.wantErrs)
			}
		})
	}
}

func TestSaveCAToSSM(t *testing.T) {
	type args struct {
		ssmSvc      ssmiface.SSMAPI
		caContents  []byte
		caParamName string
		ssmKmsKeyId string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "no kms key provided",
			args: args{
				ssmSvc:      &mockSSMClient{},
				caContents:  make([]byte, 1),
				caParamName: "schism-test-key",
				ssmKmsKeyId: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SaveCAToSSM(tt.args.ssmSvc, tt.args.caContents, tt.args.caParamName, tt.args.ssmKmsKeyId)
			if (err != nil) != tt.wantErr {
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
		want    []byte
		wantErr bool
	}{
		{
			name: "Key is present, no errors",
			args: args{ssmSvc: &mockSSMClient{}, paramName: "valid-param-name"},
			want: []byte("test-value"), wantErr: false,
		},
		{
			name: "Key not found in SSM",
			args: args{ssmSvc: &mockSSMClient{}, paramName: "non-existent-param"},
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

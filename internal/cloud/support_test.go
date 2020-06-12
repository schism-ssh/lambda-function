package cloud_test

import (
	"os"
	"reflect"
	"testing"

	"src.doom.fm/schism/lambda-function/internal/cloud"
)

type fields struct {
	CaSsmKmsKeyId       string
	CaParamPrefix       string
	CertsS3Bucket       string
	CertsS3Prefix       string
	HostCertsAuthDomain string
}

var (
	defaults = fields{
		CaSsmKmsKeyId:       "",
		CaParamPrefix:       cloud.CaParamPrefixDefault,
		CertsS3Bucket:       cloud.CertsS3BucketDefault,
		CertsS3Prefix:       "",
		HostCertsAuthDomain: "",
	}
	customEnvSet = fields{
		CaSsmKmsKeyId:       "test-key",
		CaParamPrefix:       "param-prefix",
		CertsS3Bucket:       "buckety-mc-bucketface",
		CertsS3Prefix:       "schism-certs/",
		HostCertsAuthDomain: "test.example.com",
	}
)

func TestSchismConfig_LoadEnvOrDefault(t *testing.T) {
	tests := []struct {
		name  string
		wants fields
		env   fields
	}{
		{
			name:  "empty env loads defaults",
			wants: defaults,
			env:   fields{},
		},
		{
			name:  "Loads from env correctly",
			wants: customEnvSet,
			env:   customEnvSet,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := &cloud.SchismConfig{
				CaSsmKmsKeyId:       tt.wants.CaSsmKmsKeyId,
				CaParamPrefix:       tt.wants.CaParamPrefix,
				CertsS3Bucket:       tt.wants.CertsS3Bucket,
				CertsS3Prefix:       tt.wants.CertsS3Prefix,
				HostCertsAuthDomain: tt.wants.HostCertsAuthDomain,
			}
			got := &cloud.SchismConfig{}
			cloud.HelperMustSetEnv(t, os.Setenv(cloud.CaSsmKmsKeyIdEnvVar, tt.env.CaSsmKmsKeyId))
			cloud.HelperMustSetEnv(t, os.Setenv(cloud.CaParamPrefixEnvVar, tt.env.CaParamPrefix))
			cloud.HelperMustSetEnv(t, os.Setenv(cloud.CertsS3BucketEnvVar, tt.env.CertsS3Bucket))
			cloud.HelperMustSetEnv(t, os.Setenv(cloud.CertsS3PrefixEnvVar, tt.env.CertsS3Prefix))
			cloud.HelperMustSetEnv(t, os.Setenv(cloud.HostCertsAuthDomainEnvVar, tt.env.HostCertsAuthDomain))
			got.LoadEnv()
			if !reflect.DeepEqual(got, want) {
				t.Errorf("LoadEnv() got = %+v, want %+v", got, want)
			}
		})
	}
}

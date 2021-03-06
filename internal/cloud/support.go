package cloud

import (
	"os"
)

const (
	CaSsmKmsKeyIdEnvVar       = "SCHISM_CA_KMS_KEY_ID"
	CaParamPrefixEnvVar       = "SCHISM_CA_PARAM_PREFIX"
	CertsS3BucketEnvVar       = "SCHISM_CERTS_S3_BUCKET"
	CertsS3PrefixEnvVar       = "SCHISM_CERTS_S3_PREFIX"
	HostCertsAuthDomainEnvVar = "SCHISM_HOST_CA_AUTH_DOMAIN"

	CaParamPrefixDefault = "schism-"
	CertsS3BucketDefault = "schism-signed-certificates"
)

type SchismConfig struct {
	CaSsmKmsKeyId       string
	CaParamPrefix       string
	CertsS3Bucket       string
	CertsS3Prefix       string
	HostCertsAuthDomain string
}

func (sc *SchismConfig) LoadEnv() {
	sc.CaSsmKmsKeyId = getEnv(CaSsmKmsKeyIdEnvVar, "")
	sc.CaParamPrefix = getEnv(CaParamPrefixEnvVar, CaParamPrefixDefault)
	sc.CertsS3Bucket = getEnv(CertsS3BucketEnvVar, CertsS3BucketDefault)
	sc.CertsS3Prefix = getEnv(CertsS3PrefixEnvVar, "")
	sc.HostCertsAuthDomain = getEnv(HostCertsAuthDomainEnvVar, "")
}

func getEnv(envVar string, defValue string) string {
	envValue := os.Getenv(envVar)
	if envValue == "" {
		return defValue
	}
	return envValue
}

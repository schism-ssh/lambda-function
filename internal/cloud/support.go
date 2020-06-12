package cloud

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"
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

func LookupKey(ident string, princs []string) string {
	sort.Strings(princs)
	lookupList := append([]string{ident}, princs...)
	lookupString := strings.Join(lookupList, ",")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(lookupString)))
}

func getEnv(envVar string, defValue string) string {
	envValue := os.Getenv(envVar)
	if envValue == "" {
		return defValue
	}
	return envValue
}

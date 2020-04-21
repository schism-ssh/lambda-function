package cloud

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"
)

const CaParamPrefixEnvVar = "SCHISM_CA_PARAM_PREFIX"
const CertsS3BucketEnvVar = "SCHISM_CERTS_S3_BUCKET"

func CaParamPrefix() string {
	caParamPrefix, keyFound := os.LookupEnv(CaParamPrefixEnvVar)
	if !keyFound || len(caParamPrefix) == 0 {
		caParamPrefix = "schism-"
	}
	return caParamPrefix
}

func CertsS3Bucket() string {
	certsS3Bucket, keyFound := os.LookupEnv(CertsS3BucketEnvVar)
	if !keyFound || len(certsS3Bucket) == 0 {
		certsS3Bucket = "schism-signed-certificates"
	}
	return certsS3Bucket
}

func LookupKey(ident string, princs []string) string {
	sort.Strings(princs)
	lookupList := append([]string{ident}, princs...)
	lookupString := strings.Join(lookupList, ",")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(lookupString)))
}

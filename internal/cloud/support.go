package cloud

import (
	"os"
)

const CaParamPrefixEnvVar = "SCHISM_CA_PARAM_PREFIX"

func CaParamPrefix() string {
	caParamPrefix, keyFound := os.LookupEnv(CaParamPrefixEnvVar)
	if !keyFound || len(caParamPrefix) == 0 {
		caParamPrefix = "schism-"
	}
	return caParamPrefix
}

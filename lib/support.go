package lib

import (
	"fmt"
	"os"
	"strings"
)

func CaParamName(caType string) string {
	lookupKey := fmt.Sprintf("SCHISM_%s_CA_PARAM_NAME", strings.ToUpper(caType))
	caParamName, keyFound := os.LookupEnv(lookupKey)
	if !keyFound || len(caParamName) == 0 {
		caParamName = fmt.Sprintf("schism-%s-ca-key", strings.ToLower(caType))
	}
	return caParamName
}

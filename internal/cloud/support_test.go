package cloud

import (
	"os"
	"testing"
)

func TestCaParamPrefix(t *testing.T) {
	tests := []struct {
		name        string
		envVarValue string
		want        string
	}{
		{ // User CA Key
			name:        "loaded from environment variable",
			envVarValue: "schism-aio-example-",
			want:        "schism-aio-example-",
		},
		{
			name:        "loaded default prefix",
			envVarValue: "",
			want:        "schism-",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv(CaParamPrefixEnvVar, tt.envVarValue)
			if got := CaParamPrefix(); got != tt.want {
				t.Errorf("CaParamPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func TestCertsS3Bucket(t *testing.T) {
	tests := []struct {
		name        string
		envVarValue string
		want        string
	}{
		{ // User CA Key
			name:        "loaded from environment variable",
			envVarValue: "schism-aio-signed-certificates",
			want:        "schism-aio-signed-certificates",
		},
		{
			name:        "loaded default prefix",
			envVarValue: "",
			want:        "schism-signed-certificates",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv(CertsS3BucketEnvVar, tt.envVarValue)
			if got := CertsS3Bucket(); got != tt.want {
				t.Errorf("CertsS3Bucket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLookupKey(t *testing.T) {
	type args struct {
		ident  string
		princs []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "sample host lookup key",
			args: args{
				ident:  "test.schism.example.com",
				princs: []string{"test.schism.example.com"},
			},
			want: "73f386e91cac74186f60ba0aca0a410c234b3cfafb68f20541e4c5a828a1491b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LookupKey(tt.args.ident, tt.args.princs); got != tt.want {
				t.Errorf("LookupKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

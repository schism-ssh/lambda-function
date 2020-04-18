package internal

import "testing"

func TestCaParamName(t *testing.T) {
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
			if got := CaParamName(tt.args.caType); got != tt.want {
				t.Errorf("CaParamName() = %v, want %v", got, tt.want)
			}
		})
	}
}

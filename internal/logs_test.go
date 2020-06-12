package internal

import (
	"log"
	"os"
	"testing"
)

func TestSchismLog(t *testing.T) {
	type args struct {
		dest *os.File
	}
	type logWant struct {
		flags  int
		prefix string
	}
	tests := []struct {
		name string
		args args
		want logWant
	}{
		{
			name: "creates a proper logger for `schism-lambda`",
			args: args{
				dest: os.Stdout,
			},
			want: logWant{
				flags:  log.Lmsgprefix | log.Lshortfile,
				prefix: loggerPrefix,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SchismLog(tt.args.dest)
			if got.Prefix() != tt.want.prefix {
				t.Errorf("SchismLog().Prefix() = %v, want %v", got.Prefix(), tt.want.prefix)
			}
			if got.Flags() != tt.want.flags {
				t.Errorf("SchismLog().Flags() = %v, want %v", got.Flags(), tt.want.flags)
			}
		})
	}
}

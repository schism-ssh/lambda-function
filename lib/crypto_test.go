package lib

import (
	"strings"
	"testing"
)

func TestCreateCA(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "returned []byte is not empty",
			want: "",
		},
		{
			name: "returned []byte contains 'OPENSSH PRIVATE KEY'",
			want: "OPENSSH PRIVATE KEY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateCA()
			if len(tt.want) < 1 {
				if len(got) < 1 {
					t.Errorf("createCA() = %v, wanted not an empty array", got)
				}
			} else {
				if !strings.Contains(string(got), tt.want) {
					t.Errorf("createCA() = %v, wanted it to contain %v", string(got), tt.want)
				}
			}
		})
	}
}

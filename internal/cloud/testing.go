package cloud

import "testing"

func HelperMustSetEnv(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

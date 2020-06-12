package cloud

import "testing"

func HelperMustSetEnv(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

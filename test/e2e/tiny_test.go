//go:build darwin
package e2e

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSizedTransfer(t *testing.T) {
	sizes := []int{100, 1024, 10240, 65536, 131072}
	for _, sz := range sizes {
		name := fmt.Sprintf("%dB", sz)
		if sz >= 1024 {
			name = fmt.Sprintf("%dKB", sz/1024)
		}
		t.Run(name, func(t *testing.T) {
			env := setupE2E(t)
			defer env.Cleanup()

			data := strings.Repeat("X", sz)
			os.WriteFile("/tmp/_sz_test", []byte(data), 0644)

			env.sshOutputOK("rm -f /tmp/_sz_test")
			if err := env.uploadFile("/tmp/_sz_test", "/tmp/_sz_test"); err != nil {
				t.Fatalf("upload: %v", err)
			}

			out := env.sshOutputOK("wc -c < /tmp/_sz_test")
			got := strings.TrimSpace(out)
			expected := fmt.Sprintf("%d", sz)
			if got != expected {
				t.Errorf("expected %s bytes, got %s", expected, got)
			} else {
				t.Logf("OK: %s bytes transferred", got)
			}
		})
	}
}

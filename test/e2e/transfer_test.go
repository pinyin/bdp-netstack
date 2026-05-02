//go:build darwin

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileTransferUploadDownload uploads 1MB, 10MB, and 100MB files to the VM
// via SSH pipe, verifies SHA256 integrity, then downloads them back and verifies
// again. Mirrors gvproxy's "upload and download with vz-debug" test.
func TestFileTransferUploadDownload(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	tmpDir, err := os.MkdirTemp("", "bdp-xfer-upload")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sumMap := make(map[string]string) // vmPath → sha256sum
	dstDir := "/tmp"

	// Verify sha256sum is available in VM
	env.sshOutputOK("command -v sha256sum || type sha256sum || ls /usr/bin/sha256sum")

	// Upload 1MB, 10MB, and 100MB files
	for _, size := range []int{6, 7, 8} {
		sizeName := []string{"", "", "", "", "", "", "1MB", "10MB", "100MB"}[size]
		t.Run("Upload_"+sizeName, func(t *testing.T) {
			file, err := os.CreateTemp(tmpDir, "testfile")
			if err != nil {
				t.Fatalf("create temp file: %v", err)
			}
			filePath := file.Name()

			if err := file.Truncate(int64(math.Pow10(size))); err != nil {
				t.Fatalf("truncate file: %v", err)
			}

			hasher := sha256.New()
			if _, err := io.Copy(hasher, file); err != nil {
				t.Fatalf("hash file: %v", err)
			}
			localSum := hex.EncodeToString(hasher.Sum(nil))
			file.Close()

			dstPath := filepath.Join(dstDir, filepath.Base(filePath))
			t.Logf("Upload %s (%s)", dstPath, sizeName)

			if err := env.uploadFile(filePath, dstPath); err != nil {
				t.Fatalf("upload to VM: %v", err)
			}

			out := env.sshOutputOK(fmt.Sprintf("sha256sum %s | awk '{print $1}'", dstPath))
			vmSum := strings.TrimSpace(out)
			if vmSum != localSum {
				t.Errorf("SHA256 mismatch:\n  local: %s\n  VM:    %s", localSum, vmSum)
			}

			sumMap[dstPath] = localSum
			t.Logf("Upload %s OK: %s…", sizeName, localSum[:16])
		})
	}

	// Download back and verify integrity
	t.Run("Download", func(t *testing.T) {
		dlDir, err := os.MkdirTemp("", "bdp-xfer-download")
		if err != nil {
			t.Fatalf("create download dir: %v", err)
		}
		defer os.RemoveAll(dlDir)

		for vmPath := range sumMap {
			baseName := filepath.Base(vmPath)
			localPath := filepath.Join(dlDir, baseName)
			t.Logf("Download %s", vmPath)
			if err := env.downloadFile(vmPath, localPath); err != nil {
				t.Fatalf("download from VM %s: %v", vmPath, err)
			}
		}

		entries, err := os.ReadDir(dlDir)
		if err != nil {
			t.Fatalf("read download dir: %v", err)
		}

		for _, entry := range entries {
			localPath := filepath.Join(dlDir, entry.Name())
			f, err := os.Open(localPath)
			if err != nil {
				t.Fatalf("open downloaded file: %v", err)
			}

			hasher := sha256.New()
			if _, err := io.Copy(hasher, f); err != nil {
				f.Close()
				t.Fatalf("hash downloaded file: %v", err)
			}
			f.Close()

			dlSum := hex.EncodeToString(hasher.Sum(nil))
			found := false
			for _, expected := range sumMap {
				if dlSum == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("downloaded file %s: SHA256 %s does not match any uploaded file", entry.Name(), dlSum)
			} else {
				t.Logf("Download %s OK: %s…", entry.Name(), dlSum[:16])
			}
		}
	})
}

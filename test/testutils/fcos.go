package testutils

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Minute,
}

// FCOSImage downloads the latest Fedora CoreOS image for AppleHV.
// Returns the path to the raw.gz image file.
func FCOSImage(dataDir string) (string, error) {
	url, sha, err := getFCOSDownloadURL()
	if err != nil {
		return "", fmt.Errorf("get download URL: %w", err)
	}

	filename := filepath.Base(url)
	compressedPath := filepath.Join(dataDir, filename)

	// Check if already downloaded and valid
	if stat, err := os.Stat(compressedPath); err == nil && stat.Size() > 0 {
		if verifySHA256(compressedPath, sha) {
			return compressedPath, nil
		}
		// SHA mismatch, re-download
		os.Remove(compressedPath)
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("create data dir: %w", err)
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("download FCOS image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download FCOS image: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(compressedPath)
	if err != nil {
		return "", fmt.Errorf("create file %s: %w", compressedPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		os.Remove(compressedPath)
		return "", fmt.Errorf("download incomplete: %w", err)
	}

	if !verifySHA256(compressedPath, sha) {
		os.Remove(compressedPath)
		return "", fmt.Errorf("SHA256 mismatch for %s", filename)
	}

	return compressedPath, nil
}

func coreosArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	panic("unsupported arch: " + runtime.GOARCH)
}

func getFCOSDownloadURL() (string, string, error) {
	streamURL := "https://builds.coreos.fedoraproject.org/streams/next.json"
	resp, err := httpClient.Get(streamURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch stream info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("stream info HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read stream info: %w", err)
	}

	var stream struct {
		Architectures map[string]struct {
			Artifacts map[string]struct {
				Formats map[string]struct {
					Disk *struct {
						Location string `json:"location"`
						Sha256   string `json:"sha256"`
					} `json:"disk"`
				} `json:"formats"`
			} `json:"artifacts"`
		} `json:"architectures"`
	}

	if err := json.Unmarshal(body, &stream); err != nil {
		return "", "", fmt.Errorf("parse stream info: %w", err)
	}

	arch, ok := stream.Architectures[coreosArch()]
	if !ok {
		return "", "", fmt.Errorf("arch %s not in stream", coreosArch())
	}
	applehv, ok := arch.Artifacts["applehv"]
	if !ok {
		return "", "", fmt.Errorf("applehv not in artifacts")
	}
	raw, ok := applehv.Formats["raw.gz"]
	if !ok {
		return "", "", fmt.Errorf("raw.gz format not available")
	}
	if raw.Disk == nil {
		return "", "", fmt.Errorf("no disk info")
	}

	return raw.Disk.Location, raw.Disk.Sha256, nil
}

func verifySHA256(path, expected string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	h := sha256.New()
	io.Copy(h, f)
	got := fmt.Sprintf("%x", h.Sum(nil))
	return strings.EqualFold(got, expected)
}

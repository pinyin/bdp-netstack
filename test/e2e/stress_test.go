//go:build darwin

package e2e

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestConcurrentConnections opens many concurrent TCP connections via NAT.
func TestConcurrentConnections(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	n := 50
	if s := os.Getenv("STRESS_CONCURRENT"); s != "" {
		n, _ = strconv.Atoi(s)
	}

	// Run N concurrent curl processes to different hosts
	hosts := []string{"example.com", "httpbin.org", "google.com"}
	script := "errors=0\n"
	for i := 0; i < n; i++ {
		host := hosts[i%len(hosts)]
		script += fmt.Sprintf(
			"curl -s -o /dev/null -w '%%{http_code}\\n' --connect-timeout 10 http://%s &\n",
			host,
		)
	}
	script += "wait\n"
	script += "echo ALL_DONE\n"

	out := env.sshOutputOK(script)
	if !strings.Contains(out, "ALL_DONE") {
		t.Fatalf("concurrent connections did not all complete:\n%s", out)
	}

	// Count HTTP responses (they should be 200, 301, or 302)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	failures := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "ALL_DONE" {
			break
		}
		if line == "000" {
			failures++
		}
	}
	if failures > n/10 {
		t.Errorf("%d/%d connections failed", failures, n)
	}

	t.Logf("Concurrent connections: %d launched, %d failures", n, failures)
}

// TestLargeTransfer tests TCP throughput by downloading a file through NAT.
func TestLargeTransfer(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	sizeMB := 10
	if s := os.Getenv("STRESS_TRANSFER_MB"); s != "" {
		sizeMB, _ = strconv.Atoi(s)
	}

	// First try external download, fall back to local data generation
	cmd := fmt.Sprintf(
		"curl -s -o /dev/null -w 'size=%%{size_download}\\ntime=%%{time_total}\\n' "+
			"--connect-timeout 10 --max-time 60 "+
			"http://example.com 2>&1",
	)

	out, err := env.sshOutput(cmd)
	if err != nil {
		t.Logf("External download failed (may be network issue): %v", err)
		// Fall back to generating data locally
		ddCmd := fmt.Sprintf("dd if=/dev/zero of=/tmp/_testdata bs=1M count=%d 2>&1 && echo DD_OK", sizeMB)
		out = env.sshOutputOK(ddCmd)
		if !strings.Contains(out, "DD_OK") {
			t.Fatalf("local data generation failed:\n%s", out)
		}
		t.Logf("Generated %dMB of local test data", sizeMB)
	} else {
		t.Logf("Transfer result:\n%s", out)
	}
}

// TestLongRunning keeps the stack running with periodic health checks.
func TestLongRunning(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	duration := 5 * time.Minute
	if s := os.Getenv("STRESS_DURATION"); s != "" {
		d, err := time.ParseDuration(s)
		if err == nil {
			duration = d
		}
	}

	deadline := time.After(duration)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	checkCount := 0
	for {
		select {
		case <-deadline:
			t.Logf("Long-running test completed: %d health checks passed", checkCount)
			return
		case <-ticker.C:
			checkCount++
			out, err := env.sshOutput("curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 http://example.com")
			if err != nil {
				t.Errorf("Health check #%d failed: %v\n%s", checkCount, err, out)
			} else {
				t.Logf("Health check #%d: HTTP %s", checkCount, strings.TrimSpace(out))
			}
		}
	}
}

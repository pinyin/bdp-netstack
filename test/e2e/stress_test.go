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

// TestLargeTransfer downloads a file through the NAT and verifies success.
func TestLargeTransfer(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	sizeMB := 10
	if s := os.Getenv("STRESS_TRANSFER_MB"); s != "" {
		sizeMB, _ = strconv.Atoi(s)
	}

	cmd := fmt.Sprintf(
		"curl -s -o /dev/null -w 'size=%%{size_download}\\ntime=%%{time_total}\\nspeed=%%{speed_download}\\n' "+
			"--connect-timeout 30 --max-time 120 "+
			"http://speedtest.tele2.net/%dMB.zip",
		sizeMB,
	)

	out := env.sshOutputOK(cmd)
	t.Logf("Transfer result:\n%s", out)

	if !strings.Contains(out, "size=") {
		t.Error("transfer output missing size field")
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

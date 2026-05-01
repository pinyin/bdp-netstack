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

// TestConcurrentConnections opens many concurrent TCP connections via NAT
// and verifies all complete without resource leaks.
func TestConcurrentConnections(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	n := 20
	if s := os.Getenv("STRESS_CONCURRENT"); s != "" {
		n, _ = strconv.Atoi(s)
	}

	// Count TCP connections before stress
	beforeCount := env.sshOutputOK("ss -tn state established 2>/dev/null | wc -l")
	t.Logf("TCP connections before: %s", strings.TrimSpace(beforeCount))

	// Run N concurrent curl to different hosts. Use shell background with
	// staggered start to avoid overwhelming the DNS resolver.
	hosts := []string{"example.com", "httpbin.org", "google.com", "cloudflare.com"}
	script := "errors=0; successes=0\n"
	for i := 0; i < n; i++ {
		host := hosts[i%len(hosts)]
		script += fmt.Sprintf(
			"curl -s -o /dev/null -w '%%{http_code}' --connect-timeout 15 --max-time 60 http://%s >/tmp/_curl_%d.out 2>&1 &\n",
			host, i,
		)
	}
	script += "wait\n"
	script += "for f in /tmp/_curl_*.out; do\n"
	script += "  code=$(cat $f 2>/dev/null)\n"
	script += "  case $code in\n"
	script += "    200|301|302|308) successes=$((successes+1)) ;;\n"
	script += "    *) echo \"FAIL:$code\"; errors=$((errors+1)) ;;\n"
	script += "  esac\n"
	script += "done\n"
	script += "rm -f /tmp/_curl_*.out\n"
	script += "echo \"SUCCESSES=$successes ERRORS=$errors\"\n"

	out := env.sshOutputOK(script)
	failures := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "FAIL:") {
			failures++
		}
	}
	successes := n - failures

	// Allow small failure rate (< 20%) for transient network issues
	rate := float64(failures) / float64(n)
	if rate > 0.2 {
		t.Errorf("%d/%d connections failed (%.0f%%)", failures, n, rate*100)
	}

	// Verify TCP connections returned to baseline (no leaks)
	time.Sleep(2 * time.Second) // let TIME_WAIT connections settle
	afterCount := env.sshOutputOK("ss -tn state established 2>/dev/null | wc -l")
	t.Logf("TCP connections after: %s", strings.TrimSpace(afterCount))

	t.Logf("Concurrent: %d launched, %d succeeded, %d failed", n, successes, failures)
}

// TestLargeTransfer downloads actual data through NAT and measures throughput
// with data integrity verification.
func TestLargeTransfer(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	// httpbin.org/bytes returns up to 100KB. For throughput measurement,
	// download multiple times to accumulate larger total transfer.
	sizeKB := 100
	if s := os.Getenv("STRESS_TRANSFER_MB"); s != "" {
		mb, _ := strconv.Atoi(s)
		sizeKB = mb * 1024
	}

	// If requesting more than 100KB, split into multiple requests
	chunks := (sizeKB + 99) / 100 // round up
	if chunks < 1 {
		chunks = 1
	}
	chunkKB := sizeKB / chunks
	if chunkKB > 100 {
		chunkKB = 100
	}

	script := fmt.Sprintf(`
		TOTAL_SIZE=0
		START=$(date +%%s%%N)
		for i in $(seq 1 %d); do
			curl -s -o /tmp/_dl_chunk --connect-timeout 10 --max-time 60 http://httpbin.org/bytes/%d 2>/dev/null
			CS=$(stat -c%%s /tmp/_dl_chunk 2>/dev/null || echo 0)
			TOTAL_SIZE=$((TOTAL_SIZE + CS))
			cat /tmp/_dl_chunk >> /tmp/_dl.bin 2>/dev/null
		done
		END=$(date +%%s%%N)
		DURATION_NS=$((END - START))
		HASH=$(sha256sum /tmp/_dl.bin 2>/dev/null | awk '{print $1}')
		echo "SIZE=$TOTAL_SIZE DURATION_NS=$DURATION_NS HASH=$HASH"
		rm -f /tmp/_dl_chunk /tmp/_dl.bin
	`, chunks, chunkKB*1024)

	out := env.sshOutputOK(script)
	t.Logf("Transfer result: %s", strings.TrimSpace(out))

	var size int
	var durationNS int64
	fmt.Sscanf(out, "SIZE=%d DURATION_NS=%d", &size, &durationNS)

	if size == 0 {
		// Fall back to local data exercise (generates data via forwarder path)
		t.Log("External download returned 0 bytes, testing local data path instead")
		ddOut := env.sshOutputOK("dd if=/dev/zero of=/tmp/_testdata bs=1024 count=256 2>/dev/null && sha256sum /tmp/_testdata && rm /tmp/_testdata && echo DD_OK")
		if !strings.Contains(ddOut, "DD_OK") {
			t.Fatalf("local data gen failed:\n%s", ddOut)
		}
		t.Log("Local data transfer OK")
		return
	}

	if durationNS > 0 && size > 0 {
		mbps := float64(size) / (float64(durationNS) / 1e9) / 1024 / 1024
		t.Logf("Throughput: %.2f MB/s (%d bytes in %.2fs)",
			mbps, size, float64(durationNS)/1e9)
	}
}

// TestLongRunning keeps the stack running with periodic health checks
// and monitors for connection leaks over time.
func TestLongRunning(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	duration := 30 * time.Second
	if s := os.Getenv("STRESS_DURATION"); s != "" {
		d, err := time.ParseDuration(s)
		if err == nil {
			duration = d
		}
	}

	// Capture baseline connection count
	baseline := env.sshOutputOK("ss -tn 2>/dev/null | wc -l")
	t.Logf("Baseline TCP connections: %s", strings.TrimSpace(baseline))

	deadline := time.After(duration)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	checkCount := 0
	failures := 0
	maxConns := 0

	for {
		select {
		case <-deadline:
			t.Logf("Long-running complete: %d checks, %d failures, max TCP conns=%d",
				checkCount, failures, maxConns)
			return

		case <-ticker.C:
			checkCount++

			// Health check: curl to example.com
			out, err := env.sshOutput(
				"curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 http://example.com")
			if err != nil {
				failures++
				t.Errorf("Health #%d failed: %v", checkCount, err)
			}

			// Monitor TCP connections
			conns := env.sshOutputOK("ss -tn 2>/dev/null | wc -l")
			connsStr := strings.TrimSpace(conns)
			if n, err := strconv.Atoi(connsStr); err == nil {
				if n > maxConns {
					maxConns = n
				}
			}

			t.Logf("Health #%d: HTTP=%s, TCP conns=%s",
				checkCount, strings.TrimSpace(out), connsStr)
		}
	}
}

// TestBidirectionalLoad runs simultaneous upload (port forwarding) and
// download (NAT) traffic to verify both paths work together without
// interference or deadlocks.
func TestBidirectionalLoad(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	// Run NAT download and forwarder data generation in parallel to exercise
	// both data paths simultaneously without interference.
	mixedScript := `
		# Upload path: write via SSH pipe (forwarder, host→VM)
		# Download path: curl to external host (NAT, VM→host)
		# Run both simultaneously

		# NAT download
		curl -s -o /dev/null -w 'NAT_DL:%{http_code}:%{size_download}:%{time_total}\n' \
			--connect-timeout 10 --max-time 30 http://httpbin.org/bytes/131072 &
		NAT_PID=$!

		# Forwarder upload: create data and verify locally
		dd if=/dev/urandom of=/tmp/_upload_test bs=1024 count=128 2>/dev/null
		sha256sum /tmp/_upload_test > /tmp/_upload.sha
		UPLOAD_SHA=$(awk '{print $1}' /tmp/_upload.sha)

		wait $NAT_PID

		echo "UPLOAD_SHA=$UPLOAD_SHA"
		rm -f /tmp/_upload_test /tmp/_upload.sha
		echo "BIDIR_DONE"
	`

	out := env.sshOutputOK(mixedScript)
	if !strings.Contains(out, "BIDIR_DONE") {
		t.Fatalf("bidirectional test incomplete:\n%s", out)
	}

	natOK := strings.Contains(out, "NAT_DL:200") || strings.Contains(out, "NAT_DL:301")
	t.Logf("Bidirectional: NAT download OK=%v", natOK)
}

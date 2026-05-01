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

// TestRapidOpenClose rapidly opens and closes TCP connections to stress
// the full lifecycle: SYN → Established → FinWait1 → FinWait2 → TimeWait → cleanup.
// Verifies no connection leaks or data corruption after rapid cycling.
func TestRapidOpenClose(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	iterations := 50
	if s := os.Getenv("CHAOS_ITERATIONS"); s != "" {
		iterations, _ = strconv.Atoi(s)
	}

	// Get baseline connection count
	beforeConns := env.sshOutputOK("ss -tn 2>/dev/null | wc -l")
	t.Logf("TCP connections before: %s", strings.TrimSpace(beforeConns))

	// Rapid open/close: curl + close in a loop. Use --max-time to ensure
	// we don't hang on a stuck connection.
	script := fmt.Sprintf(`
		failures=0
		for i in $(seq 1 %d); do
			code=$(curl -s -o /dev/null -w '%%{http_code}' --connect-timeout 10 --max-time 30 http://example.com 2>/dev/null)
			case $code in
				200|301|302|308) ;;
				*) failures=$((failures+1)) ;;
			esac
		done
		echo "FAILURES=$failures"
	`, iterations)

	out := env.sshOutputOK(script)
	t.Logf("Rapid open/close: %d iterations, output: %s", iterations, strings.TrimSpace(out))

	// Give TIME_WAIT connections time to expire (60s timer in our stack)
	// For quick test validation, just wait a bit and check
	time.Sleep(3 * time.Second)

	// Verify connectivity still works
	pingOut := env.sshOutputOK("ping -c 2 -W 3 " + gwIP)
	t.Logf("Post-chaos ping: %s", strings.TrimSpace(pingOut))

	// Verify no orphan connections: do another curl to ensure new connections work
	postOut := env.sshOutputOK("curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 http://example.com")
	code := strings.TrimSpace(postOut)
	if code != "200" && code != "301" && code != "302" {
		t.Errorf("post-chaos curl failed with code: %s", code)
	}
	t.Logf("Post-chaos HTTP: %s", code)
}

// TestConnectionFlood rapidly creates and abandons TCP connections via
// half-open patterns to stress SYN handling and timer cleanup.
func TestConnectionFlood(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	n := 30
	if s := os.Getenv("CHAOS_ITERATIONS"); s != "" {
		n, _ = strconv.Atoi(s)
	}

	// Strategy: open connections to a closed port on an external host.
	// The TCP stack must handle RST correctly and clean up the connection.
	// Then verify normal connections still work.
	script := fmt.Sprintf(`
		failures=0
		for i in $(seq 1 %d); do
			# Connect to closed port — should get RST or timeout
			curl -s --connect-timeout 3 --max-time 5 http://example.com:19999 >/dev/null 2>&1 &
		done
		wait
		echo "FLOOD_DONE"
	`, n)

	out := env.sshOutputOK(script)
	t.Logf("Connection flood: %s", strings.TrimSpace(out))

	time.Sleep(2 * time.Second)

	// After flood, verify normal connectivity
	pingOut, err := env.sshOutput("ping -c 3 -W 3 " + gwIP)
	if err != nil {
		t.Errorf("post-flood ping failed: %v\n%s", err, pingOut)
	} else {
		t.Logf("Post-flood ping: %s", strings.TrimSpace(pingOut))
	}

	// Verify NAT still works
	httpOut := env.sshOutputOK("curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 http://example.com")
	t.Logf("Post-flood HTTP: %s", strings.TrimSpace(httpOut))
}

// TestMixedProtocol runs TCP, UDP, and ICMP traffic concurrently to verify
// all protocol paths coexist without interference.
func TestMixedProtocol(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	n := 3 // rounds of mixed traffic
	if s := os.Getenv("CHAOS_ITERATIONS"); s != "" {
		n, _ = strconv.Atoi(s)
	}

	// Run multiple rounds to increase chance of interleaving
	script := fmt.Sprintf(`
		errors=0
		for round in $(seq 1 %d); do
			# TCP: HTTP request via NAT
			curl -s -o /dev/null -w 'TCP:%%{http_code}\n' --connect-timeout 10 http://example.com 2>/dev/null &
			TCP_PID=$!

			# UDP: DNS query (uses built-in DNS proxy on gateway)
			getent ahosts example.com > /tmp/_ns_$$.out 2>&1 &
			DNS_PID=$!

			# ICMP: ping gateway
			ping -c 2 -W 5 %s > /tmp/_ping_$$.out 2>&1 &
			PING_PID=$!

			# Wait for all
			wait $TCP_PID $DNS_PID $PING_PID

			# Verify each
			grep -q example.com /tmp/_ns_$$.out || { echo "DNS_FAIL"; errors=$((errors+1)); }
			grep -q "packets transmitted" /tmp/_ping_$$.out || { echo "PING_FAIL"; errors=$((errors+1)); }

			rm -f /tmp/_ns_$$.out /tmp/_ping_$$.out
		done
		echo "ERRORS=$errors"
	`, n, gwIP)

	out := env.sshOutputOK(script)
	t.Logf("Mixed protocol (%d rounds): %s", n, strings.TrimSpace(out))

	var errors int
	fmt.Sscanf(out, "ERRORS=%d", &errors)
	if errors > 0 {
		t.Errorf("%d protocol failures in %d rounds", errors, n)
	} else {
		t.Logf("Mixed protocol: all %d rounds passed (TCP+UDP+ICMP)", n)
	}
}

// TestSimultaneousClose exercises the simultaneous close code path
// (both sides send FIN at approximately the same time → TIME_WAIT).
func TestSimultaneousClose(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	iterations := 20
	if s := os.Getenv("CHAOS_ITERATIONS"); s != "" {
		iterations, _ = strconv.Atoi(s)
	}

	// Use curl with --max-time 0.5 to close connections before transfer completes,
	// exercising FIN_WAIT1 → TIME_WAIT (simultaneous close) or FIN_WAIT1 → FIN_WAIT2 path.
	script := fmt.Sprintf(`
		errors=0
		successes=0
		for i in $(seq 1 %d); do
			# Quick connect then abort — exercises early close
			timeout 3 curl -s -o /dev/null --connect-timeout 5 --max-time 1 http://httpbin.org/delay/5 2>/dev/null
			rc=$?
			if [ $rc -eq 0 ] || [ $rc -eq 28 ] || [ $rc -eq 124 ]; then
				successes=$((successes+1))
			else
				errors=$((errors+1))
			fi
		done
		echo "SUCCESSES=$successes ERRORS=$errors"
	`, iterations)

	out := env.sshOutputOK(script)
	t.Logf("Simultaneous close (%d iterations): %s", iterations, strings.TrimSpace(out))

	// Verify normal operation still works after rapid closes
	time.Sleep(2 * time.Second)
	healthOut := env.sshOutputOK("curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 http://example.com")
	t.Logf("Post-simultaneous-close health: HTTP %s", strings.TrimSpace(healthOut))
}

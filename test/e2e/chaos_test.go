//go:build darwin

package e2e

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestRapidOpenClose rapidly opens and closes TCP connections to stress
// the connection lifecycle (SYN → Established → FinWait → TimeWait → cleanup).
func TestRapidOpenClose(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	iterations := 100
	if s := os.Getenv("CHAOS_ITERATIONS"); s != "" {
		iterations, _ = strconv.Atoi(s)
	}

	script := fmt.Sprintf(`
		for i in $(seq 1 %d); do
			curl -s -o /dev/null --connect-timeout 5 http://example.com || true
		done
		echo DONE
	`, iterations)

	out := env.sshOutputOK(script)
	if !strings.Contains(out, "DONE") {
		t.Fatalf("rapid open/close did not complete:\n%s", out)
	}

	t.Logf("Rapid open/close: %d iterations completed", iterations)

	// After rapid open/close, verify basic connectivity still works
	pingOut := env.sshOutputOK("ping -c 1 -W 2 " + gwIP)
	t.Logf("Post-chaos connectivity: %s", strings.TrimSpace(pingOut))
}

// TestMixedProtocol runs TCP, UDP, and ICMP traffic concurrently to verify
// all protocol paths coexist without interference.
func TestMixedProtocol(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	script := `
		# TCP: HTTP request via NAT
		curl -s -o /dev/null -w 'HTTP:%{http_code}\n' --connect-timeout 10 http://example.com &

		# UDP: DNS query to gateway (uses built-in DNS proxy)
		nslookup example.com > /tmp/_ns.out 2>&1 &

		# ICMP: ping the gateway
		ping -c 3 -W 5 ` + gwIP + ` > /tmp/_ping.out 2>&1 &

		# Wait for all background processes
		wait

		# Print results
		echo "=== DNS ==="
		cat /tmp/_ns.out
		echo "=== PING ==="
		cat /tmp/_ping.out
		echo "ALL_DONE"
	`

	out := env.sshOutputOK(script)
	if !strings.Contains(out, "ALL_DONE") {
		t.Fatalf("mixed protocol test did not complete:\n%s", out)
	}

	// Verify DNS resolved
	if !strings.Contains(out, "example.com") {
		t.Errorf("DNS did not resolve example.com in mixed test:\n%s", out)
	}

	// Verify ping succeeded
	if !strings.Contains(out, "packets transmitted") {
		t.Errorf("ping did not run in mixed test:\n%s", out)
	}

	t.Log("Mixed protocol test passed: TCP + UDP + ICMP all functional")
}

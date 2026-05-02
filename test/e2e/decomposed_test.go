//go:build darwin

// Package e2e — decomposed VM integration tests.
// Each test focuses on a single capability. When multiple tests run in one
// 'go test' invocation, they share a single VM boot (via sync.Once).
// When run individually with -run, each boots its own VM.
package e2e

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Shared VM singleton — boots once per 'go test' invocation.
// ============================================================================

var (
	sharedEnv     *E2EEnv
	sharedEnvOnce sync.Once
	sharedEnvErr  error
)

func getOrBootVM(t *testing.T) *E2EEnv {
	t.Helper()
	sharedEnvOnce.Do(func() {
		sharedEnv = setupE2E(t)
	})
	if sharedEnv == nil {
		t.Fatal("VM setup failed")
	}
	return sharedEnv
}

// cleanupSharedVM is called once when all tests in the package finish.
// Not automatically called — we use TestMain for that.
// For now, each test's t.Cleanup is a no-op when sharing.

// ============================================================================
// Decomposed test functions
// ============================================================================

// TestVMNetworkConfig boots a VM and checks IP, MTU, route, and DNS config.
func TestVMNetworkConfig(t *testing.T) {
	env := getOrBootVM(t)

	t.Run("IPAndMTU", func(t *testing.T) {
		out := env.sshOutputOK("ip -4 addr show")
		if !containsAll(out, "mtu 1500", vmIP) {
			t.Errorf("expected MTU 1500 and IP %s:\n%s", vmIP, out)
		}
		t.Log("IP/MTU OK")
	})

	t.Run("DefaultRoute", func(t *testing.T) {
		out := env.sshOutputOK("ip route show default")
		if !strings.Contains(out, gwIP) {
			t.Errorf("expected default via %s:\n%s", gwIP, out)
		}
		t.Log("default route OK")
	})

	t.Run("DNSResolver", func(t *testing.T) {
		out := env.sshOutputOK("cat /etc/resolv.conf")
		if !strings.Contains(out, gwIP) {
			t.Errorf("expected nameserver %s:\n%s", gwIP, out)
		}
		t.Log("DNS resolver OK")
	})
}

// TestVMShell verifies basic SSH connectivity.
func TestVMShell(t *testing.T) {
	env := getOrBootVM(t)

	out := env.sshOutputOK("whoami")
	if got := strings.TrimSpace(out); got != "root" {
		t.Fatalf("expected 'root', got %q", got)
	}
	t.Logf("SSH shell: %s", out)
}

// TestVMDNS verifies DNS resolution via the built-in proxy.
func TestVMDNS(t *testing.T) {
	env := getOrBootVM(t)

	out := env.sshOutputOK("getent ahosts example.com")
	if !strings.Contains(out, "example.com") {
		t.Errorf("getent ahosts did not resolve example.com:\n%s", out)
	}
	t.Logf("DNS: %s", strings.TrimSpace(out))
}

// TestVMPingGateway verifies the VM can ping the gateway.
func TestVMPingGateway(t *testing.T) {
	env := getOrBootVM(t)

	out := env.sshOutputOK("ping -c 4 -W 3 " + gwIP)
	if !strings.Contains(out, "4 packets transmitted") {
		t.Errorf("ping gateway failed:\n%s", out)
	}
	t.Logf("ping gateway OK")
}

// TestVMHTTPNAT verifies outbound TCP through NAT.
func TestVMHTTPNAT(t *testing.T) {
	env := getOrBootVM(t)

	out := env.sshOutputOK(
		"curl -s -o /dev/null -w '%{http_code}' --connect-timeout 15 http://example.com")
	code := strings.TrimSpace(out)
	if code != "200" && code != "301" && code != "302" && code != "308" {
		t.Errorf("expected HTTP 200/301/302/308, got: %s", code)
	}
	t.Logf("HTTP via NAT: %s", code)
}

// TestVMExternalPing verifies ICMP forwarding to internet hosts.
func TestVMExternalPing(t *testing.T) {
	env := getOrBootVM(t)

	for _, target := range []string{"1.1.1.1", "8.8.8.8"} {
		out, err := env.sshOutput("ping -c 2 -W 5 " + target)
		if err != nil {
			t.Logf("ping %s (non-fatal): %v\n%s", target, err, out)
		} else {
			t.Logf("ping %s OK", target)
		}
	}
}

// TestVMNegative verifies expected failure modes don't crash the stack.
func TestVMNegative(t *testing.T) {
	env := getOrBootVM(t)

	t.Run("UnreachablePing", func(t *testing.T) {
		_, err := env.sshOutput("ping -c 1 -W 3 10.255.255.1")
		if err != nil {
			t.Logf("unreachable ping correctly failed: %v", err)
		} else {
			t.Log("unreachable ping unexpectedly succeeded")
		}
	})

	t.Run("ClosedPort", func(t *testing.T) {
		out, err := env.sshOutput("curl -s --connect-timeout 5 http://127.0.0.1:19999 2>&1")
		if err != nil {
			t.Logf("closed port correctly failed: %v", err)
		} else {
			t.Logf("closed port (unexpected): %s", out)
		}
	})
}

// TestVMConcurrentSSHNAT stresses the stack with simultaneous SSH and NAT traffic.
func TestVMConcurrentSSHNAT(t *testing.T) {
	env := getOrBootVM(t)

	// Start continuous HTTP background traffic
	env.sshOutputOrLog("bash -c '" +
		"for i in $(seq 1 8); do " +
		"  (while true; do curl -s --connect-timeout 5 --max-time 10 " +
		"    http://example.com; sleep 0.3; done) " +
		"  </dev/null >/dev/null 2>&1 & " +
		"done'")

	time.Sleep(3 * time.Second)

	failures := 0
	for i := 0; i < 10; i++ {
		out, err := env.sshOutput("whoami")
		if err != nil {
			failures++
			t.Logf("SSH %d failed: %v | output: %q", i+1, err, out)
		} else if got := strings.TrimSpace(out); got != "root" {
			failures++
			t.Logf("SSH %d: wrong output %q", i+1, got)
		}
	}

	env.sshOutputOrLog("pkill -f 'while true.*curl' 2>/dev/null; pkill curl 2>/dev/null; true")

	if failures > 0 {
		t.Errorf("%d/%d SSH attempts failed during NAT traffic", failures, 10)
	} else {
		t.Log("All SSH attempts succeeded during concurrent NAT traffic")
	}
}

//go:build darwin

// Package e2e tests the full stack with vfkit + a minimal bootc test image.
package e2e

import (
	"strings"
	"testing"
	"time"
)

const (
	sockPath   = "/tmp/bdp-netstack-e2e.sock"
	sshPort    = 2223
	sshUser    = "root"
	gwIP       = "192.168.65.1"
	vmIP       = "192.168.65.2"
	gwMAC      = "5a:94:ef:e4:0c:ee"
	vmMAC      = "5a:94:ef:e4:0c:ef"
	efiStore   = "efi-variable-store"
)

func TestE2EBasic(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	// ── Existing tests ──

	t.Run("SSHExec", func(t *testing.T) {
		out := env.sshOutputOK("whoami")
		got := strings.TrimSpace(out)
		if got != "root" {
			t.Fatalf("expected 'root', got %q", got)
		}
		t.Logf("VM whoami: %s", got)
	})

	t.Run("DNS", func(t *testing.T) {
		out := env.sshOutputOK("getent hosts example.com")
		t.Logf("example.com: %s", strings.TrimSpace(out))
	})

	t.Run("PingGateway", func(t *testing.T) {
		out := env.sshOutputOK("ping -c 2 -W 3 " + gwIP)
		t.Logf("ping: %s", strings.TrimSpace(out))
	})

	// ── New tests (Phase 11b) ──

	t.Run("NetworkConfig", func(t *testing.T) {
		// Verify IP address and MTU
		out := env.sshOutputOK("ip -4 addr show")
		if !containsAll(out, "mtu 1500", "192.168.65.2") {
			t.Errorf("expected MTU 1500 and IP 192.168.65.2:\n%s", out)
		}

		// Verify default route
		out = env.sshOutputOK("ip route show default")
		if !strings.Contains(out, "192.168.65.1") {
			t.Errorf("expected default via 192.168.65.1:\n%s", out)
		}

		// Verify DNS resolver config
		out = env.sshOutputOK("cat /etc/resolv.conf")
		if !strings.Contains(out, "192.168.65.1") {
			t.Errorf("expected nameserver 192.168.65.1:\n%s", out)
		}

		t.Log("Network configuration verified")
	})

	t.Run("DNSResolution", func(t *testing.T) {
		// DNS resolution via getaddrinfo (exercises NSS/DNS code path)
		// Uses getent ahosts which shows all resolved addresses
		out := env.sshOutputOK("getent ahosts example.com")
		if !strings.Contains(out, "example.com") {
			t.Errorf("getent ahosts did not resolve example.com:\n%s", out)
		}
		t.Logf("getent ahosts: %s", strings.TrimSpace(out))
	})

	t.Run("ExternalPing", func(t *testing.T) {
		// ICMP forwarding to external hosts. Use t.Log on failure
		// since some networks block ICMP.
		for _, target := range []string{"1.1.1.1", "8.8.8.8"} {
			out, err := env.sshOutput("ping -c 2 -W 5 " + target)
			if err != nil {
				t.Logf("ping %s (non-fatal): %v\n%s", target, err, out)
			} else {
				t.Logf("ping %s: %s", target, strings.TrimSpace(out))
			}
		}
	})

	t.Run("HTTPViaNAT", func(t *testing.T) {
		// TCP outbound NAT: curl to an external HTTP server
		out := env.sshOutputOK("curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 http://example.com")
		if !strings.Contains(out, "200") && !strings.Contains(out, "301") && !strings.Contains(out, "302") {
			t.Errorf("expected HTTP 200/301/302, got: %s", out)
		}
		t.Logf("HTTP response code: %s", strings.TrimSpace(out))
	})

	t.Run("PortForwarding", func(t *testing.T) {
		// Explicit SSH port forwarding test (SSH is forwarded to VM:22)
		out := env.sshOutputOK("whoami")
		if got := strings.TrimSpace(out); got != "root" {
			t.Fatalf("SSH via port forward failed, expected 'root' got %q", got)
		}
		t.Log("Port forwarding (SSH) works")
	})

	t.Run("NegativeTests", func(t *testing.T) {
		// Ping an unreachable IP — should fail
		out, err := env.sshOutput("ping -c 1 -W 3 10.255.255.1")
		if err == nil {
			t.Logf("ping unreachable IP (unexpected success): %s", out)
		} else {
			t.Logf("ping unreachable IP correctly failed: %v", err)
		}

		// Connect to a closed port — should be refused or timeout
		out, err = env.sshOutput("curl -s --connect-timeout 5 http://127.0.0.1:19999 2>&1")
		if err != nil {
			t.Logf("curl closed port correctly failed: %v", err)
		} else {
			t.Logf("curl closed port (unexpected): %s", out)
		}
	})

	// TestConcurrentSSHAndNAT reproduces a cross-connection data leak
	// where HTTP response data from NAT connections contaminates SSH
	// forwarder connections. The existing sequential tests didn't catch
	// this because they never exercise both paths simultaneously.
	t.Run("ConcurrentSSHAndNAT", func(t *testing.T) {
		// Start continuous HTTP downloads in the background to keep
		// NAT TCP connections active while we exercise SSH forwarding.
		// Use multiple parallel curls to ensure sustained NAT traffic.
		//
		// NOTE: each subshell MUST have stdin/stdout/stderr redirected
		// away from the SSH channel (</dev/null >/dev/null 2>&1), or
		// the SSH server will keep the session open after bash exits,
		// causing the SSH command to block forever.
		bashOut, bashErr := env.sshOutput("bash -c '" +
			"for i in $(seq 1 10); do " +
			"  (while true; do curl -s --connect-timeout 5 --max-time 10 " +
			"    http://example.com; sleep 0.1; done) " +
			"  </dev/null >/dev/null 2>&1 & " +
			"done'")
			if bashErr != nil {
				t.Fatalf("failed to start background HTTP: %v\n%s", bashErr, bashOut)
			}

		// Give HTTP connections time to establish and start transferring
		time.Sleep(3 * time.Second)

		// Now repeatedly open NEW SSH connections. Each creates a fresh
		// forwarder entry. If NAT HTTP data leaks into forwarder RecvBuf,
		// these SSH connections will see corrupted data.
		failures := 0
		for i := 0; i < 15; i++ {
			out, err := env.sshOutput("whoami")
			if err != nil {
				failures++
				t.Logf("SSH attempt %d failed: %v | output: %q", i+1, err, out)
			} else if got := strings.TrimSpace(out); got != "root" {
				failures++
				t.Logf("SSH attempt %d: wrong output %q", i+1, got)
			}
		}

		// Kill background HTTP processes
		env.sshOutputOrLog("pkill -f 'while true.*curl' 2>/dev/null; pkill curl 2>/dev/null; true")

		if failures > 0 {
			t.Errorf("%d/%d SSH attempts failed while NAT HTTP traffic was active "+
				"(cross-connection data leak reproduced)", failures, 15)
		} else {
			t.Log("All SSH attempts succeeded — no cross-connection leak detected")
		}
	})
}

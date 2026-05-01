//go:build darwin

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// iperf3BinDir is the directory containing prebuilt iperf3 aarch64 binaries.
var iperf3BinDir = filepath.Join(
	os.Getenv("HOME"), "developer", "POC", "bdp-netstack", "test", "image", "output",
)

// TestIperfForwarderThroughput measures TCP and UDP throughput via the port
// forwarder. iperf3 server runs in the VM, client runs on the host connecting
// through the forwarded port.
//
// This mirrors gvproxy's test/performance.sh forwarder section.
func TestIperfForwarderThroughput(t *testing.T) {
	iperfPort := "15201"
	env := setupE2E(t, iperfPort+":"+vmIP+":5201")
	defer env.Cleanup()

	// SCP iperf3 binary and library to VM
	iperfBin := filepath.Join(iperf3BinDir, "iperf3.arm64")
	iperfLib := filepath.Join(iperf3BinDir, "libiperf.so.0")
	if _, err := os.Stat(iperfBin); err != nil {
		t.Skipf("iperf3 aarch64 binary not found at %s — build it first", iperfBin)
	}
	if err := env.scpToVM(iperfBin, "/tmp"); err != nil {
		t.Fatalf("scp iperf3 to VM: %v", err)
	}
	if err := env.scpToVM(iperfLib, "/tmp"); err != nil {
		t.Fatalf("scp libiperf to VM: %v", err)
	}
	env.sshOutputOK("chmod +x /tmp/iperf3.arm64")

	// Start iperf3 server in VM (background)
	serverCmd := env.SSHCommand("LD_LIBRARY_PATH=/tmp /tmp/iperf3.arm64 -s -D -1")
	if out, err := serverCmd.CombinedOutput(); err != nil {
		t.Fatalf("start iperf3 server in VM: %v\n%s", err, out)
	}
	time.Sleep(1 * time.Second) // let server stabilize

	iperf3Host := filepath.Join("/opt/homebrew", "bin", "iperf3")

	t.Run("TCP_send", func(t *testing.T) {
		cmd := exec.Command(iperf3Host, "-c", "127.0.0.1", "-p", iperfPort, "-t", "5")
		out, _ := cmd.CombinedOutput()
		t.Logf("TCP send (host→VM):\n%s", summarizeIperf3(out))
	})

	t.Run("TCP_recv", func(t *testing.T) {
		cmd := exec.Command(iperf3Host, "-c", "127.0.0.1", "-p", iperfPort, "-t", "5", "-R")
		out, _ := cmd.CombinedOutput()
		t.Logf("TCP recv (VM→host):\n%s", summarizeIperf3(out))
	})

	t.Run("UDP_send", func(t *testing.T) {
		cmd := exec.Command(iperf3Host, "-c", "127.0.0.1", "-p", iperfPort, "-t", "5", "-u", "-b", "100M", "-l", "9216")
		out, _ := cmd.CombinedOutput()
		t.Logf("UDP send (host→VM, jumbo):\n%s", summarizeIperf3(out))
	})

	t.Run("UDP_recv", func(t *testing.T) {
		cmd := exec.Command(iperf3Host, "-c", "127.0.0.1", "-p", iperfPort, "-t", "5", "-u", "-b", "100M", "-R", "-l", "9216")
		out, _ := cmd.CombinedOutput()
		t.Logf("UDP recv (VM→host, jumbo):\n%s", summarizeIperf3(out))
	})

	// Kill iperf3 server in VM
	env.sshOutputOrLog("pkill iperf3.arm64 || true")
}

// TestHTTPThroughputViaNAT measures TCP throughput via NAT by downloading
// larger files through the NAT from the VM to external servers.
//
// This validates TCP NAT throughput for real-world HTTP workloads.
func TestHTTPThroughputViaNAT(t *testing.T) {
	env := setupE2E(t)
	defer env.Cleanup()

	// Download 1MB, 10MB from httpbin.org (range requests)
	// httpbin supports /range/ which returns specified number of bytes
	sizes := map[string]int{
		"1MB":  1_000_000,
		"10MB": 10_000_000,
	}

	for name, size := range sizes {
		t.Run("Download_"+name, func(t *testing.T) {
			url := fmt.Sprintf("http://httpbin.org/range/%d", size)
			cmd := fmt.Sprintf(
				"curl -s -o /dev/null -w 'size=%%{size_download} speed=%%{speed_download} time=%%{time_total}' "+
					"--connect-timeout 10 --max-time 120 '%s'",
				url,
			)
			out, err := env.sshOutput(cmd)
			if err != nil {
				t.Logf("HTTP download %s failed (may be network issue): %v\n%s", name, err, out)
			} else {
				t.Logf("NAT download %s: %s", name, strings.TrimSpace(out))
			}
		})
	}
}

// summarizeIperf3 extracts the key throughput lines from iperf3 output.
func summarizeIperf3(out []byte) string {
	lines := strings.Split(string(out), "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Keep sender/receiver summary lines and error lines
		if strings.Contains(trimmed, "sender") ||
			strings.Contains(trimmed, "receiver") ||
			strings.Contains(trimmed, "sec") ||
			strings.Contains(trimmed, "Mbits") ||
			strings.Contains(trimmed, "Gbits") ||
			strings.Contains(trimmed, "KBytes") ||
			strings.Contains(trimmed, "MBytes") ||
			strings.Contains(trimmed, "error") ||
			strings.Contains(trimmed, "unable") {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		// Fallback: show last 3 non-empty lines
		nonEmpty := []string{}
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				nonEmpty = append(nonEmpty, strings.TrimSpace(line))
			}
		}
		if len(nonEmpty) > 3 {
			nonEmpty = nonEmpty[len(nonEmpty)-3:]
		}
		return strings.Join(nonEmpty, "\n")
	}
	return strings.Join(result, "\n")
}

// cleanupIperf3 is a helper to kill stale iperf3 processes between tests.
func cleanupIperf3() {
	exec.Command("pkill", "-f", "iperf3").Run()
	time.Sleep(200 * time.Millisecond)
}

// startHostIperf3Server starts an iperf3 server on the host and returns the
// process for cleanup. It listens on all interfaces.
func startHostIperf3Server(t *testing.T) *exec.Cmd {
	t.Helper()

	cleanupIperf3()

	iperf3Host := filepath.Join("/opt/homebrew", "bin", "iperf3")
	cmd := exec.Command(iperf3Host, "-s", "-1")
	cmd.Stderr = os.Stderr
	// Use process group so we can kill children
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start host iperf3 server: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // let server stabilize
	return cmd
}

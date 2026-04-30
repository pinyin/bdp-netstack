//go:build darwin

// Package e2e tests the full stack with vfkit + a minimal bootc test image.
package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// 1. Locate or build the test disk image
	projRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("find project root: %v", err)
	}
	imageDir := filepath.Join(projRoot, "test", "image")

	// Try multiple locations for the disk image
	candidates := []string{
		filepath.Join(imageDir, "output", "disk.raw"),
		"/Users/pinyin/tmp/bdp-netstack-image-arm64/disk.raw",
	}
	var rawImage string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			rawImage = c
			break
		}
	}
	if rawImage == "" {
		t.Skipf("Test disk image not found at any of: %v. Build it:\n"+
			"  cd test/image && ./build.sh", candidates)
	}

	privateKeyFile := filepath.Join(imageDir, "test_key")
	if _, err := os.Stat(privateKeyFile); err != nil {
		t.Fatalf("SSH test key not found: %s", privateKeyFile)
	}

	// Fix key permissions (ssh requires 0600)
	os.Chmod(privateKeyFile, 0600)

	// 2. Clean any leftover sockets and efi store
	os.Remove(sockPath)
	efiStorePath := filepath.Join(os.TempDir(), "bdp-e2e-"+efiStore)
	os.Remove(efiStorePath)
	defer os.Remove(efiStorePath)

	// 3. Build bdp-netstack binary
	tmpDir, err := os.MkdirTemp("", "bdp-e2e")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	binPath := filepath.Join(tmpDir, "bdp-netstack")
	if out, err := exec.Command("go", "build", "-o", binPath,
		"github.com/pinyin/bdp-netstack/cmd/bdp-netstack").CombinedOutput(); err != nil {
		t.Fatalf("build bdp-netstack: %v\n%s", err, out)
	}

	// 4. Start bdp-netstack
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	forwardSpec := strconv.Itoa(sshPort) + ":" + vmIP + ":22"
	stackCmd := exec.CommandContext(ctx, binPath,
		"--socket", sockPath,
		"--gateway-ip", gwIP,
		"--gateway-mac", gwMAC,
		"--bpt", "1ms",
		forwardSpec,
	)
	stackCmd.Stderr = os.Stderr
	stackCmd.Stdout = os.Stdout
	if err := stackCmd.Start(); err != nil {
		t.Fatalf("start bdp-netstack: %v", err)
	}
	defer stackCmd.Process.Kill()

	// Wait for socket to appear
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("bdp-netstack socket didn't appear: %v", err)
	}

	// 5. Start vfkit
	vfkitPath, err := exec.LookPath("vfkit")
	if err != nil {
		t.Skipf("vfkit not found: %v", err)
	}

	consoleLogPath := filepath.Join(os.TempDir(), "bdp-e2e-console.log")
	vfkitArgs := []string{
		"--cpus", "2",
		"--memory", "2048",
		"--bootloader", "efi,variable-store=" + efiStorePath + ",create",
		"--device", "virtio-blk,path=" + rawImage,
		"--device", "virtio-net,unixSocketPath=" + sockPath + ",mac=" + vmMAC,
		"--device", "virtio-serial,logFilePath=" + consoleLogPath,
	}
	vfkitCmd := exec.CommandContext(ctx, vfkitPath, vfkitArgs...)
	vfkitCmd.Stderr = os.Stderr
	vfkitCmd.Stdout = os.Stdout
	if err := vfkitCmd.Start(); err != nil {
		t.Fatalf("start vfkit: %v", err)
	}
	defer vfkitCmd.Process.Kill()

	// 6. Wait for SSH to be available
	sshReady := false
	for i := 0; i < 120; i++ {
		cmd := sshCommand(privateKeyFile, "whoami")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(out)) == sshUser {
			sshReady = true
			break
		}
		errStr := stderr.String()
		if len(errStr) > 200 {
			errStr = errStr[:200] + "..."
		}
		if i < 10 || i%15 == 0 {
			t.Logf("waiting for SSH... (%ds) err=%v out=%q stderr=%q", i*2, err, strings.TrimSpace(string(out)), errStr)
		}
		time.Sleep(2 * time.Second)
	}
	if !sshReady {
		t.Fatal("SSH never became available")
	}
	t.Log("SSH is ready")

	// Settle time for network
	time.Sleep(3 * time.Second)

	// 7. Run basic connectivity tests
	t.Run("SSHExec", func(t *testing.T) {
		cmd := sshCommand(privateKeyFile, "whoami")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("ssh whoami: %v\nstderr: %s", err, stderr.String())
		}
		if strings.TrimSpace(string(out)) != "root" {
			t.Fatalf("expected 'root', got %q", strings.TrimSpace(string(out)))
		}
		t.Logf("VM whoami: %s", strings.TrimSpace(string(out)))
	})

	t.Run("DNS", func(t *testing.T) {
		cmd := sshCommand(privateKeyFile, "getent hosts example.com")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("DNS lookup: %v\nstderr: %s", err, stderr.String())
		}
		t.Logf("example.com: %s", strings.TrimSpace(string(out)))
	})

	t.Run("PingGateway", func(t *testing.T) {
		cmd := sshCommand(privateKeyFile, "ping -c 2 -W 3 "+gwIP)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ping gateway: %v\n%s", err, out)
		}
		t.Logf("ping: %s", strings.TrimSpace(string(out)))
	})
}

func sshCommand(privateKeyFile string, cmd_ string) *exec.Cmd {
	return exec.Command("ssh",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "ConnectTimeout=5",
		"-i", privateKeyFile,
		"-p", strconv.Itoa(sshPort),
		sshUser+"@127.0.0.1",
		cmd_,
	)
}

func findProjectRoot() (string, error) {
	// Find the project root by looking for go.mod
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fallback: use GOPATH or module cache
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		return filepath.Join(gopath, "src", "github.com/pinyin/bdp-netstack"), nil
	}
	// Last resort
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(filename))), nil
}

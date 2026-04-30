//go:build darwin

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// E2EEnv holds the state for an e2e test run.
type E2EEnv struct {
	Ctx        context.Context
	Cancel     context.CancelFunc
	PrivateKey string
	StackCmd   *exec.Cmd
	VfkitCmd   *exec.Cmd
	TmpDir     string
	t          *testing.T
}

// setupE2E builds the stack, starts vfkit, and waits for SSH readiness.
func setupE2E(t *testing.T) *E2EEnv {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	projRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("find project root: %v", err)
	}
	imageDir := filepath.Join(projRoot, "test", "image")

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
	os.Chmod(privateKeyFile, 0600)

	// Clean leftovers
	os.Remove(sockPath)
	efiStorePath := filepath.Join(os.TempDir(), "bdp-e2e-"+efiStore)
	os.Remove(efiStorePath)

	// Build binary
	tmpDir, err := os.MkdirTemp("", "bdp-e2e")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	binPath := filepath.Join(tmpDir, "bdp-netstack")
	if out, err := exec.Command("go", "build", "-o", binPath,
		"github.com/pinyin/bdp-netstack/cmd/bdp-netstack").CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("build bdp-netstack: %v\n%s", err, out)
	}

	// Start stack
	ctx, cancel := context.WithCancel(context.Background())

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
		cancel()
		os.RemoveAll(tmpDir)
		t.Fatalf("start bdp-netstack: %v", err)
	}

	// Wait for socket
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(sockPath); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		t.Fatalf("bdp-netstack socket didn't appear: %v", err)
	}

	// Start vfkit
	vfkitPath, err := exec.LookPath("vfkit")
	if err != nil {
		cancel()
		os.RemoveAll(tmpDir)
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
		cancel()
		os.RemoveAll(tmpDir)
		t.Fatalf("start vfkit: %v", err)
	}

	env := &E2EEnv{
		Ctx:        ctx,
		Cancel:     cancel,
		PrivateKey: privateKeyFile,
		StackCmd:   stackCmd,
		VfkitCmd:   vfkitCmd,
		TmpDir:     tmpDir,
		t:          t,
	}

	// Wait for SSH
	sshReady := false
	for i := 0; i < 120; i++ {
		cmd := env.SSHCommand("whoami")
		out, err := cmd.Output()
		if err == nil && string(out) == sshUser+"\n" {
			sshReady = true
			break
		}
		if i < 10 || i%15 == 0 {
			t.Logf("waiting for SSH... (%ds)", i*2)
		}
		time.Sleep(2 * time.Second)
	}
	if !sshReady {
		env.Cleanup()
		t.Fatal("SSH never became available")
	}
	t.Log("SSH is ready")

	time.Sleep(3 * time.Second) // network settle
	return env
}

// SSHCommand returns an exec.Cmd for running a command in the VM via SSH.
func (e *E2EEnv) SSHCommand(cmd string) *exec.Cmd {
	return exec.Command("ssh",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "ConnectTimeout=5",
		"-i", e.PrivateKey,
		"-p", strconv.Itoa(sshPort),
		sshUser+"@127.0.0.1",
		cmd,
	)
}

// Cleanup tears down the test environment.
func (e *E2EEnv) Cleanup() {
	if e.StackCmd != nil && e.StackCmd.Process != nil {
		e.StackCmd.Process.Kill()
	}
	if e.VfkitCmd != nil && e.VfkitCmd.Process != nil {
		e.VfkitCmd.Process.Kill()
	}
	e.Cancel()
	if e.TmpDir != "" {
		os.RemoveAll(e.TmpDir)
	}
}

// sshOutput runs a command via SSH and returns combined output.
func (e *E2EEnv) sshOutput(cmd string) (string, error) {
	c := e.SSHCommand(cmd)
	out, err := c.CombinedOutput()
	return string(out), err
}

// sshOutputOK runs a command and calls t.Fatal on error.
func (e *E2EEnv) sshOutputOK(cmd string) string {
	out, err := e.sshOutput(cmd)
	if err != nil {
		e.t.Fatalf("%s: %v\n%s", cmd, err, out)
	}
	return out
}

// sshOutputOrLog runs a command and logs the error but does not fail the test.
func (e *E2EEnv) sshOutputOrLog(cmd string) string {
	out, err := e.sshOutput(cmd)
	if err != nil {
		e.t.Logf("%s (non-fatal): %v\n%s", cmd, err, out)
	}
	return out
}

// sshExpect runs a command and fails if the output does not contain the needle.
func (e *E2EEnv) sshExpect(cmd, needle string) {
	out := e.sshOutputOK(cmd)
	if !strings.Contains(out, needle) {
		e.t.Fatalf("%s: expected output to contain %q, got:\n%s", cmd, needle, out)
	}
}

// sshCmdOK is like sshOutputOK but prints the command description on failure.
func (e *E2EEnv) sshCmdOK(desc, cmd string) string {
	out, err := e.sshOutput(cmd)
	if err != nil {
		e.t.Fatalf("%s (%s): %v\n%s", desc, cmd, err, out)
	}
	return out
}

func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}

func findProjectRoot() (string, error) {
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
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		return filepath.Join(gopath, "src", "github.com/pinyin/bdp-netstack"), nil
	}
	return filepath.Join(os.Getenv("HOME"), "developer", "POC", "bdp-netstack"), nil
}

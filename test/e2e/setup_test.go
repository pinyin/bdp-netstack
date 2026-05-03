//go:build darwin

package e2e

import (
	"context"
	"fmt"
	"net"
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
	VMCmd      *exec.Cmd
	TmpDir     string
	t          *testing.T
}

// setupE2E builds the stack, starts vz-debug, and waits for SSH readiness.
func setupE2E(t *testing.T, extraForwards ...string) *E2EEnv {
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

	// Copy SSH key to local temp — avoids NFS attribute hangs
	srcKeyPath := filepath.Join(imageDir, "test_key")
	keyData, err := os.ReadFile(srcKeyPath)
	if err != nil {
		t.Fatalf("SSH test key not found at %s: %v", imageDir, err)
	}
	localKey, err := os.CreateTemp("", "bdp-e2e-key-*")
	if err != nil {
		t.Fatalf("create temp key file: %v", err)
	}
	localKeyPath := localKey.Name()
	if _, err := localKey.Write(keyData); err != nil {
		localKey.Close()
		os.Remove(localKeyPath)
		t.Fatalf("write temp key: %v", err)
	}
	localKey.Close()
	os.Chmod(localKeyPath, 0600)
	privateKeyFile := localKeyPath

	// Clean leftovers and wait for resources to be released.
	// Previous test runs or stale processes may still hold the socket or port.
	os.Remove(sockPath)
	efiStorePath := filepath.Join(os.TempDir(), "bdp-e2e-"+efiStore)
	os.Remove(efiStorePath)

	// Wait for the unix socket path to be fully released by any stale process.
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(sockPath); os.IsNotExist(err) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for the SSH port to be available. On macOS, ports can linger
	// in TIME_WAIT after process termination, causing "address already in use".
	waitPortFree(t, sshPort)

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

	// Open log files so we can inspect them even if the test is killed.
	// Save e2e log to /tmp (not tmpDir) so it survives cleanup.
	e2eLogPath := filepath.Join(os.TempDir(), "bdp-e2e-test.log")
	e2eLog, err := os.Create(e2eLogPath)
	if err != nil {
		t.Fatalf("create e2e log: %v", err)
	}
	stackLog, err := os.Create(filepath.Join(tmpDir, "stack.log"))
	if err != nil {
		t.Fatalf("create stack log: %v", err)
	}
	vmLog, err := os.Create(filepath.Join(tmpDir, "vz-debug.log"))
	if err != nil {
		t.Fatalf("create vz-debug log: %v", err)
	}
	logf := func(format string, args ...interface{}) {
		msg := fmt.Sprintf("%s "+format+"\n", append([]interface{}{time.Now().Format("15:04:05.000")}, args...)...)
		e2eLog.WriteString(msg)
		t.Logf(format, args...)
	}
	logf("=== TestE2EBasic starting ===")
	logf("log files: e2e=%s, stack=%s/stack.log, vz-debug=%s/vz-debug.log", e2eLogPath, tmpDir, tmpDir)

	// Start stack
	ctx, cancel := context.WithCancel(context.Background())

	forwardSpec := strconv.Itoa(sshPort) + ":" + vmIP + ":22"
	args := []string{
		"--socket", sockPath,
		"--gateway-ip", gwIP,
		"--gateway-mac", gwMAC,
		"--bpt", "1ms",
		forwardSpec,
	}
	args = append(args, extraForwards...)
	stackCmd := exec.CommandContext(ctx, binPath, args...)
	stackCmd.Stderr = stackLog
	stackCmd.Stdout = stackLog
	logf("starting bdp-netstack: %s %v", binPath, args)
	if err := stackCmd.Start(); err != nil {
		logf("FAIL: start bdp-netstack: %v", err)
		cancel()
		os.RemoveAll(tmpDir)
		t.Fatalf("start bdp-netstack: %v", err)
	}
	logf("bdp-netstack started (pid=%d)", stackCmd.Process.Pid)

	// Wait for socket
	logf("waiting for socket %s...", sockPath)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(sockPath); err != nil {
		logf("FAIL: socket didn't appear: %v", err)
		cancel()
		os.RemoveAll(tmpDir)
		t.Fatalf("bdp-netstack socket didn't appear: %v", err)
	}
	logf("socket ready")

	// Start vz-debug (custom VZ-based VM launcher with frame-level debug logging)
	vzDebugPath := filepath.Join(projRoot, "..", "..", "..", "..", "developer", "POC", "vz-debug", ".build", "debug", "vz-debug")
	if _, err := os.Stat(vzDebugPath); err != nil {
		// Try absolute path
		vzDebugPath = filepath.Join(os.Getenv("HOME"), "developer", "POC", "vz-debug", ".build", "debug", "vz-debug")
	}
	if _, err := os.Stat(vzDebugPath); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		t.Fatalf("vz-debug not found at %s: build it with: cd ~/developer/POC/vz-debug && swift build", vzDebugPath)
	}

	consoleLogPath := filepath.Join(os.TempDir(), "bdp-e2e-console.log")
	vmArgs := []string{
		"--cpus", "2",
		"--memory", "2048",
		"--efi-store", efiStorePath,
		"--disk", rawImage,
		"--socket", sockPath,
		"--mac", vmMAC,
		"--console-log", consoleLogPath,
	}
	vmCmd := exec.CommandContext(ctx, vzDebugPath, vmArgs...)
	vmCmd.Stderr = vmLog
	vmCmd.Stdout = vmLog
	logf("starting vz-debug: %s %v", vzDebugPath, vmArgs)
	if err := vmCmd.Start(); err != nil {
		logf("FAIL: start vz-debug: %v", err)
		cancel()
		os.RemoveAll(tmpDir)
		t.Fatalf("start vz-debug: %v", err)
	}
	logf("vz-debug started (pid=%d)", vmCmd.Process.Pid)

	env := &E2EEnv{
		Ctx:        ctx,
		Cancel:     cancel,
		PrivateKey: privateKeyFile,
		StackCmd:   stackCmd,
		VMCmd:      vmCmd,
		TmpDir:     tmpDir,
		t:          t,
	}

	// Wait for SSH. Use Output() (stdout only) because SSH prints
	// warnings like "Permanently added ... to known hosts" on stderr,
	// which would prevent CombinedOutput from matching "root".
	logf("waiting for SSH on 127.0.0.1:%d...", sshPort)
	sshReady := false
	for i := 0; i < 90; i++ {
		cmd := env.SSHCommand("whoami")
		out, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(out)) == sshUser {
			sshReady = true
			logf("SSH ready at attempt %d (%.0fs)", i+1, float64(i+1))
			break
		}
		if i < 15 || i%15 == 0 {
			errStr := ""
			if err != nil {
				errStr = fmt.Sprintf(" err=%v", err)
				// Re-run with CombinedOutput for stderr diagnostics
				if diagOut, _ := env.SSHCommand("whoami").CombinedOutput(); len(diagOut) > 0 {
					out = diagOut
				}
			}
			outStr := strings.TrimSpace(string(out))
			if len(outStr) > 80 {
				outStr = outStr[:80] + "..."
			}
			logf("SSH attempt %d/90%s out=%q", i+1, errStr, outStr)
		}
		time.Sleep(1 * time.Second)
	}
	if !sshReady {
		logf("FAIL: SSH never became available after 90 attempts")
		env.Cleanup()
		t.Fatal("SSH never became available")
	}

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
// Waits for processes to exit so ports are released before the next test starts.
func (e *E2EEnv) Cleanup() {
	e.t.Logf("Cleanup: killing processes...")
	e.Cancel()

	// Kill and wait for stack process so port 2223 is released
	if e.StackCmd != nil && e.StackCmd.Process != nil {
		e.StackCmd.Process.Kill()
		// Wait up to 5 seconds for process to exit
		done := make(chan struct{})
		go func() {
			e.StackCmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			e.t.Logf("stack process did not exit in time")
		}
	}

	// Kill and wait for VM process
	if e.VMCmd != nil && e.VMCmd.Process != nil {
		e.VMCmd.Process.Kill()
		done := make(chan struct{})
		go func() {
			e.VMCmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			e.t.Logf("VM process did not exit in time")
		}
	}

	e.t.Logf("Logs preserved at: /tmp/bdp-e2e-test.log")
	if e.TmpDir != "" {
		e.t.Logf("Stack+vz-debug logs at: %s/", e.TmpDir)
	}
}

// sshOutput runs a command via SSH and returns combined output.
// Uses Output() (stdout only) to avoid SSH stderr warnings polluting results.
func (e *E2EEnv) sshOutput(cmd string) (string, error) {
	c := e.SSHCommand(cmd)
	out, err := c.Output()
	return string(out), err
}

// sshOutputOK runs a command and calls t.Fatal on error.
func (e *E2EEnv) sshOutputOK(cmd string) string {
	out, err := e.sshOutput(cmd)
	if err != nil {
		// Re-run with CombinedOutput to get stderr for diagnosis
		c := e.SSHCommand(cmd)
		fullOut, _ := c.CombinedOutput()
		e.t.Fatalf("%s: %v\n%s", cmd, err, string(fullOut))
	}
	return out
}

// sshOutputOrLog runs a command and logs the error but does not fail the test.
func (e *E2EEnv) sshOutputOrLog(cmd string) string {
	out, err := e.sshOutput(cmd)
	if err != nil {
		c := e.SSHCommand(cmd)
		fullOut, _ := c.CombinedOutput()
		e.t.Logf("%s (non-fatal): %v\n%s", cmd, err, string(fullOut))
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

// scp copies a file to or from the VM via SCP.
func (e *E2EEnv) scp(src, dst string) error {
	cmd := exec.Command("/usr/bin/scp",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", e.PrivateKey,
		"-P", strconv.Itoa(sshPort),
		src, dst,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp %s %s: %v\n%s", src, dst, err, string(out))
	}
	return nil
}

// scpToVM copies a local file to the VM's destination directory.
func (e *E2EEnv) scpToVM(srcPath, dstDir string) error {
	return e.scp(srcPath, fmt.Sprintf("%s@127.0.0.1:%s", sshUser, dstDir))
}

// scpFromVM copies a file from the VM to a local destination directory.
func (e *E2EEnv) scpFromVM(srcPath, dstDir string) error {
	return e.scp(fmt.Sprintf("%s@127.0.0.1:%s", sshUser, srcPath), dstDir)
}

// uploadFile uploads a local file to the VM via SSH pipe (cat | ssh "cat > dst").
// This avoids SCP dependencies entirely.
func (e *E2EEnv) uploadFile(localPath, vmPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()

	cmd := e.SSHCommand(fmt.Sprintf("cat > %s", vmPath))
	cmd.Stdin = f
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("upload to %s: %v\n%s", vmPath, err, string(out))
	}
	return nil
}

// downloadFile downloads a file from the VM via SSH pipe (ssh "cat src" > localPath).
func (e *E2EEnv) downloadFile(vmPath, localPath string) error {
	f, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", localPath, err)
	}
	defer f.Close()

	cmd := e.SSHCommand(fmt.Sprintf("cat %s", vmPath))
	cmd.Stdout = f
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("download %s: %v", vmPath, err)
	}
	return nil
}

func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}

// waitPortFree blocks until the TCP port is available or the test fails.
func waitPortFree(t interface{ Fatal(...interface{}) }, port int) {
	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			ln.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("port", port, "still in use after 10 seconds")
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

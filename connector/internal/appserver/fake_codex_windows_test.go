//go:build windows

package appserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Windows cannot execute a shebang script, so the fake Codex CLI the tests
// drive is a real executable image compiled from this source. Every behaviour
// is selected by environment so one image serves the whole package.
const fakeCodexSource = `package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		version()
		return
	}
	switch os.Getenv("FAKE_CODEX_MODE") {
	case "descendant":
		block()
	case "marker":
		record("FAKE_CODEX_MARKER", "started")
		block()
	case "spawn":
		spawn()
		block()
	case "appserver":
		handshake()
		spawn()
		block()
	case "bootstrap":
		bootstrap()
	case "revalidate":
		audit("app-server")
		handshake()
		block()
	case "stderrleak":
		handshake()
		os.Stderr.WriteString(os.Getenv("FAKE_CODEX_STDERR"))
		os.Exit(23)
	case "version":
		// This mode answers --version and nothing else.
		os.Exit(60)
	default:
		os.Exit(60)
	}
}

func version() {
	audit("version")
	banner := environment("FAKE_CODEX_VERSION_STDOUT", "codex-cli 0.147.0\n")
	if drift := os.Getenv("FAKE_CODEX_DRIFT_FILE"); drift != "" {
		if _, err := os.Stat(drift); err == nil {
			banner = environment("FAKE_CODEX_DRIFT_STDOUT", banner)
		}
	}
	if diagnostic := os.Getenv("FAKE_CODEX_VERSION_STDERR"); diagnostic != "" {
		os.Stderr.WriteString(diagnostic)
	}
	os.Stdout.WriteString(banner)
}

func environment(variable, fallback string) string {
	if value := os.Getenv(variable); value != "" {
		return value
	}
	return fallback
}

func audit(entry string) {
	path := os.Getenv("FAKE_CODEX_AUDIT")
	if path == "" {
		return
	}
	handle, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(66)
	}
	if _, err := handle.WriteString(entry + "\n"); err != nil {
		os.Exit(67)
	}
	if err := handle.Close(); err != nil {
		os.Exit(68)
	}
}

func record(variable, contents string) {
	path := os.Getenv(variable)
	if path == "" {
		os.Exit(61)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		os.Exit(62)
	}
}

func spawn() {
	descendant := exec.Command(os.Args[0])
	descendant.Env = append(os.Environ(), "FAKE_CODEX_MODE=descendant")
	if err := descendant.Start(); err != nil {
		os.Exit(63)
	}
	record("FAKE_CODEX_PID", strconv.Itoa(descendant.Process.Pid))
}

func handshake() {
	reader := bufio.NewReader(os.Stdin)
	readLine(reader, 64)
	fmt.Println(initializeResult)
	readLine(reader, 65)
}

func bootstrap() {
	requireArgument(1, "app-server", 41)
	requireArgument(2, "--listen", 42)
	requireArgument(3, "stdio://", 43)
	reader := bufio.NewReader(os.Stdin)
	readLine(reader, 44)
	fmt.Println(initializeResult)
	readLine(reader, 45)
	fmt.Println("{\"jsonrpc\":\"2.0\",\"method\":\"turn/started\",\"params\":{\"threadId\":\"t\",\"turn\":{\"id\":\"turn-1\",\"items\":[],\"status\":\"inProgress\"}},\"emittedAtMs\":1785945600000}")
	readLine(reader, 46)
	fmt.Println("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"data\":[{\"id\":\"model\",\"model\":\"model\",\"displayName\":\"Model\",\"description\":\"Test model\",\"isDefault\":true,\"hidden\":false,\"defaultReasoningEffort\":\"medium\",\"supportedReasoningEfforts\":[]}]}}")
	block()
}

const initializeResult = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"codexHome\":\"C:/fake-codex-home\",\"platformFamily\":\"windows\",\"platformOs\":\"windows\",\"userAgent\":\"fake\"}}"

func requireArgument(index int, want string, code int) {
	if len(os.Args) <= index || os.Args[index] != want {
		os.Exit(code)
	}
}

func readLine(reader *bufio.Reader, code int) {
	if _, err := reader.ReadString('\n'); err != nil {
		os.Exit(code)
	}
}

func block() {
	time.Sleep(10 * time.Minute)
}
`

var (
	fakeCodexOnce   sync.Once
	fakeCodexImage  string
	fakeCodexFailed error
	fakeCodexRoot   string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeCodexRoot != "" {
		_ = os.RemoveAll(fakeCodexRoot)
	}
	os.Exit(code)
}

// buildFakeCodex compiles the fake Codex CLI once per test binary and returns
// the shared image; callers select behaviour with the fakeCodex* helpers.
func buildFakeCodex(t *testing.T) string {
	t.Helper()
	fakeCodexOnce.Do(func() { fakeCodexImage, fakeCodexFailed = compileFakeCodex() })
	if fakeCodexFailed != nil {
		t.Skipf("fake Codex CLI is unavailable: %v", fakeCodexFailed)
	}
	return fakeCodexImage
}

func compileFakeCodex() (string, error) {
	tool, err := exec.LookPath("go")
	if err != nil {
		tool = filepath.Join(runtime.GOROOT(), "bin", "go.exe")
		if _, statErr := os.Stat(tool); statErr != nil {
			return "", fmt.Errorf("go toolchain is unavailable: %w", err)
		}
	}
	root, err := os.MkdirTemp("", "sub2api-fake-codex")
	if err != nil {
		return "", err
	}
	fakeCodexRoot = root
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(fakeCodexSource), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fakecodex\n"), 0o600); err != nil {
		return "", err
	}
	image := filepath.Join(root, "codex.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, tool, "build", "-o", image, ".")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build fake codex: %w\n%s", err, output)
	}
	return image, nil
}

func fakeCodexVersion(t *testing.T, stdout, stderr string) string {
	t.Helper()
	image := buildFakeCodex(t)
	t.Setenv("FAKE_CODEX_MODE", "version")
	t.Setenv("FAKE_CODEX_VERSION_STDOUT", stdout)
	t.Setenv("FAKE_CODEX_VERSION_STDERR", stderr)
	return image
}

func fakeCodexBootstrap(t *testing.T) string {
	t.Helper()
	image := buildFakeCodex(t)
	t.Setenv("FAKE_CODEX_MODE", "bootstrap")
	return image
}

func fakeCodexRevalidation(t *testing.T, audit, drifted string) string {
	t.Helper()
	image := buildFakeCodex(t)
	t.Setenv("FAKE_CODEX_MODE", "revalidate")
	t.Setenv("FAKE_CODEX_AUDIT", audit)
	t.Setenv("FAKE_CODEX_DRIFT_FILE", drifted)
	t.Setenv("FAKE_CODEX_DRIFT_STDOUT", "codex-cli 9.9.9\n")
	return image
}

func fakeCodexStderrLeak(t *testing.T, diagnostic string) string {
	t.Helper()
	image := buildFakeCodex(t)
	t.Setenv("FAKE_CODEX_MODE", "stderrleak")
	t.Setenv("FAKE_CODEX_STDERR", diagnostic)
	return image
}

// fakeCodexE2E gives the shared tests/e2e/fake_codex.py an executable image on a
// platform with no shebang. The launcher is a real .exe because the Connector
// refuses .cmd and .bat shims, and it forwards stdio and the exit status
// untouched so the app-server protocol runs exactly as it does on POSIX. Python
// ends up a grandchild of the Connector, which also exercises the job object's
// process-tree termination.
func fakeCodexE2E(t *testing.T, dir, source string) string {
	t.Helper()
	interpreter, err := exec.LookPath("python")
	if err != nil {
		interpreter, err = exec.LookPath("py")
		if err != nil {
			t.Skipf("no Python interpreter is available to run %s: %v", source, err)
		}
	}
	script, err := filepath.Abs(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	tool, err := exec.LookPath("go")
	if err != nil {
		tool = filepath.Join(runtime.GOROOT(), "bin", "go.exe")
		if _, statErr := os.Stat(tool); statErr != nil {
			t.Skipf("go toolchain is unavailable: %v", err)
		}
	}
	root := filepath.Join(dir, "launcher")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := fmt.Sprintf(fakeCodexLauncherSource, interpreter, script)
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(launcher), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fakecodexlauncher\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(dir, "codex.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, tool, "build", "-o", image, ".")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake codex launcher: %v\n%s", err, output)
	}
	return image
}

const fakeCodexLauncherSource = `package main

import (
	"errors"
	"os"
	"os/exec"
)

const (
	interpreter = %q
	script      = %q
)

func main() {
	command := exec.Command(interpreter, append([]string{script}, os.Args[1:]...)...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		os.Exit(1)
	}
}
`

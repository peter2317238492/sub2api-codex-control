package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

func TestOpenLogFileAppliesTheFixedRotationCap(t *testing.T) {
	if logRotateBytes != 4<<20 {
		t.Fatalf("log rotation cap = %d bytes", logRotateBytes)
	}
	log, err := OpenLogFile(stateDirectory(t), "connector.log")
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	defer log.Close()
	if log.limit != logRotateBytes {
		t.Fatalf("log limit = %d, want %d", log.limit, logRotateBytes)
	}
}

func TestLogFileIsCreatedAsAPrivateStateFile(t *testing.T) {
	stateDir := stateDirectory(t)
	log, err := OpenLogFile(stateDir, "connector.log")
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	if _, err := log.Write([]byte("connector started\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, err := securefile.StatPrivateFile(filepath.Join(stateDir, "connector.log"))
	if err != nil {
		t.Fatalf("StatPrivateFile: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("log file mode = %v", info.Mode())
	}
}

func TestLogFileAppendsAcrossReopen(t *testing.T) {
	stateDir := stateDirectory(t)
	for _, record := range []string{"first\n", "second\n"} {
		log, err := OpenLogFile(stateDir, "connector.log")
		if err != nil {
			t.Fatalf("OpenLogFile: %v", err)
		}
		if _, err := log.Write([]byte(record)); err != nil {
			t.Fatalf("write %q: %v", record, err)
		}
		if err := log.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "connector.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\nsecond\n" {
		t.Fatalf("log file = %q, want appended records", data)
	}
}

func TestLogFileRotatesAtItsCapAndKeepsOnePreviousGeneration(t *testing.T) {
	stateDir := stateDirectory(t)
	const limit = 32
	record := []byte("0123456789abcdef\n")
	log, err := openLogFile(stateDir, "connector.log", limit)
	if err != nil {
		t.Fatalf("openLogFile: %v", err)
	}
	for index := 0; index < 8; index++ {
		if _, err := log.Write(record); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > limit {
			t.Fatalf("generation %s is %d bytes, above the %d byte cap", entry.Name(), info.Size(), limit)
		}
	}
	if len(names) != 2 {
		t.Fatalf("state directory holds %v, want exactly one current and one previous generation", names)
	}
	for _, name := range []string{"connector.log", "connector.log.1"} {
		info, err := securefile.StatPrivateFile(filepath.Join(stateDir, name))
		if err != nil {
			t.Fatalf("StatPrivateFile %s: %v", name, err)
		}
		if string(mustRead(t, filepath.Join(stateDir, name))) != string(record) {
			t.Fatalf("generation %s does not hold one whole record (%d bytes)", name, info.Size())
		}
	}
}

func TestLogFileWriteAfterCloseFails(t *testing.T) {
	log, err := OpenLogFile(stateDirectory(t), "connector.log")
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := log.Write([]byte("late\n")); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("write after close error = %v", err)
	}
}

func TestLogFilePathMustNameAPrivateChildOfTheStateDirectory(t *testing.T) {
	stateDir := stateDirectory(t)
	outside := filepath.Join(t.TempDir(), "connector.log")
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "relative name", path: "connector.log", want: ""},
		{name: "absolute child", path: filepath.Join(stateDir, "connector.log"), want: ""},
		{name: "empty", path: "", want: "empty"},
		{name: "blank", path: "   ", want: "empty"},
		{name: "parent escape", path: filepath.Join("..", "connector.log"), want: "directly inside"},
		{name: "nested directory", path: filepath.Join("logs", "connector.log"), want: "directly inside"},
		{name: "outside state directory", path: outside, want: "directly inside"},
		{name: "state directory itself", path: stateDir, want: "directly inside"},
		{name: "other state object", path: "device-credentials.json", want: "must end in .log"},
		{name: "bare suffix", path: ".log", want: "must end in .log"},
		{name: "alternate data stream", path: "connector.log:stream", want: "must end in .log"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := resolveLogPath(stateDir, test.path)
			if test.want == "" {
				if err != nil {
					t.Fatalf("resolveLogPath(%q) = %v", test.path, err)
				}
				if resolved != filepath.Join(stateDir, "connector.log") {
					t.Fatalf("resolved log path = %q", resolved)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("resolveLogPath(%q) error = %v, want %q", test.path, err, test.want)
			}
		})
	}
}

func TestLogFileRequiresAnAbsoluteStateDirectory(t *testing.T) {
	if _, err := resolveLogPath("state", "connector.log"); err == nil ||
		!strings.Contains(err.Error(), "absolute state directory") {
		t.Fatalf("relative state directory error = %v", err)
	}
}

func stateDirectory(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

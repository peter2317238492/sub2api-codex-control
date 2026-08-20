//go:build windows

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

// An ordinary Windows reader withholds FILE_SHARE_DELETE, which denies the
// DELETE access rotation needs, so an operator reading the log blocks it. The
// sink has to survive that for as long as the read rather than for the life of
// the process: a scheduled task has no console, so a retired log file is
// indistinguishable from a connector that stopped running.
func TestLogFileRotationBlockedByAReaderKeepsTheSinkAndTheCap(t *testing.T) {
	stateDir := stateDirectory(t)
	const limit = 32
	record := []byte("0123456789abcdef\n")
	log, err := openLogFile(stateDir, "connector.log", limit)
	if err != nil {
		t.Fatalf("openLogFile: %v", err)
	}
	defer log.Close()
	if _, err := log.Write(record); err != nil {
		t.Fatalf("first write: %v", err)
	}
	current := filepath.Join(stateDir, "connector.log")
	reader, err := os.Open(current)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	if _, err := log.Write(record); err == nil || !strings.Contains(err.Error(), "rotate connector log file") {
		t.Fatalf("rotation blocked by a reader returned %v", err)
	}
	info, err := securefile.StatPrivateFile(current)
	if err != nil {
		t.Fatalf("StatPrivateFile: %v", err)
	}
	if info.Size() > limit {
		t.Fatalf("blocked rotation grew the log to %d bytes, above the %d byte cap", info.Size(), limit)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Write(record); err != nil {
		t.Fatalf("write after the reader closed: %v", err)
	}
	for name, want := range map[string]string{
		"connector.log":   string(record),
		"connector.log.1": string(record),
	} {
		path := filepath.Join(stateDir, name)
		if _, err := securefile.StatPrivateFile(path); err != nil {
			t.Fatalf("StatPrivateFile %s: %v", name, err)
		}
		if got := string(mustRead(t, path)); got != want {
			t.Fatalf("generation %s = %q, want %q", name, got, want)
		}
	}
}

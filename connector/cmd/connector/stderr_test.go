package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	connectorRuntime "github.com/peter2317238492/sub2api-codex-control/connector/internal/runtime"
)

type failingWriter struct{}

func (w *failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func (w *failingWriter) Close() error { return nil }

func TestStderrSinkWithoutALogFileIsAConsolePassThrough(t *testing.T) {
	var console bytes.Buffer
	sink := newStderrSink(&console)
	for _, record := range []string{"first\n", "second\n"} {
		written, err := sink.Write([]byte(record))
		if err != nil {
			t.Fatalf("write %q: %v", record, err)
		}
		if written != len(record) {
			t.Fatalf("write %q returned %d bytes", record, written)
		}
	}
	if console.String() != "first\nsecond\n" {
		t.Fatalf("console = %q", console.String())
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestStderrSinkDuplicatesConsoleRecordsIntoTheLogFile(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	logFile, err := connectorRuntime.OpenLogFile(stateDir, "connector.log")
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	var console bytes.Buffer
	sink := newStderrSink(&console)
	sink.Attach(logFile)
	if _, err := sink.Write([]byte("codex app-server unavailable\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	logged, err := os.ReadFile(filepath.Join(stateDir, "connector.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(logged) != console.String() {
		t.Fatalf("log file = %q, console = %q", logged, console.String())
	}
}

func TestStderrSinkKeepsLoggingWhenTheConsoleIsUnavailable(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	logFile, err := connectorRuntime.OpenLogFile(stateDir, "connector.log")
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	console := &failingWriter{}
	sink := newStderrSink(console)
	sink.Attach(logFile)
	if _, err := sink.Write([]byte("connector started\n")); err == nil {
		t.Fatal("console write error was hidden from the caller")
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	logged, err := os.ReadFile(filepath.Join(stateDir, "connector.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(logged) != "connector started\n" {
		t.Fatalf("log file = %q", logged)
	}
}

func TestStderrSinkReportsAFailingLogFileOnceAndKeepsTheConsoleIntact(t *testing.T) {
	var console bytes.Buffer
	sink := newStderrSink(&console)
	broken := &failingWriter{}
	sink.Attach(broken)
	for index := 0; index < 3; index++ {
		if _, err := sink.Write([]byte("record\n")); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if strings.Count(console.String(), "log file write failed") != 1 {
		t.Fatalf("console = %q, want exactly one log failure notice", console.String())
	}
	if strings.Count(console.String(), "record\n") != 3 {
		t.Fatalf("console = %q, want every record", console.String())
	}
}

func TestPairingCodeNoticeReportsOnlyThePrivateFilePath(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	logFile, err := connectorRuntime.OpenLogFile(stateDir, "connector.log")
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	codePath := filepath.Join(stateDir, "pairing-code.json")
	code := "ABCD-EFGH-IJKL-MNOP"
	published, err := json.Marshal(map[string]string{"code": code, "expires_at": "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codePath, published, 0o600); err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	sink := newStderrSink(&console)
	sink.Attach(logFile)
	reportPairingCodePath(sink, codePath)
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	logged, err := os.ReadFile(filepath.Join(stateDir, "connector.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := "Pairing code written to " + codePath + "\n"
	if string(logged) != want {
		t.Fatalf("log file = %q, want %q", logged, want)
	}
	if console.String() != want {
		t.Fatalf("console = %q, want %q", console.String(), want)
	}
	if strings.Contains(string(logged), code) || strings.Contains(console.String(), code) {
		t.Fatal("pairing code reached the connector log")
	}
}

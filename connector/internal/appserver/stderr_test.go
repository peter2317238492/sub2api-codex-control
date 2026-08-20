package appserver

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChildStderrCaptureSuppressesContentsAndBoundsReport(t *testing.T) {
	var output bytes.Buffer
	capture := newChildStderrCapture(&output)
	secret := "Authorization: Bearer sk-sensitive-provider-token"
	payload := []byte(strings.Repeat(secret+"\n", 4096))

	if written, err := capture.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", written, err, len(payload))
	}
	capture.report()
	capture.report()

	report := output.String()
	if strings.Contains(report, secret) || strings.Contains(report, "sensitive-provider-token") {
		t.Fatalf("stderr contents leaked into report: %q", report)
	}
	want := "codex app-server stderr suppressed (bytes>=65536)\n"
	if report != want {
		t.Fatalf("report = %q, want %q", report, want)
	}
	if len(report) > 128 {
		t.Fatalf("report length = %d, want at most 128", len(report))
	}
}

func TestChildStderrCaptureReportsSmallWriteWithoutContents(t *testing.T) {
	var output bytes.Buffer
	capture := newChildStderrCapture(&output)

	_, _ = capture.Write([]byte("private prompt"))
	capture.report()

	if got, want := output.String(), "codex app-server stderr suppressed (bytes=14)\n"; got != want {
		t.Fatalf("report = %q, want %q", got, want)
	}
}

func TestChildStderrCaptureIsSafeForConcurrentWrites(t *testing.T) {
	capture := newChildStderrCapture(nil)
	data := []byte(strings.Repeat("x", 1024))
	var writers sync.WaitGroup
	for range 32 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for range 16 {
				if written, err := capture.Write(data); err != nil || written != len(data) {
					t.Errorf("Write() = (%d, %v), want (%d, nil)", written, err, len(data))
				}
			}
		}()
	}
	writers.Wait()
	capture.report()

	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.observed != maxObservedStderrBytes || !capture.truncated || !capture.reported {
		t.Fatalf("capture state = observed:%d truncated:%t reported:%t", capture.observed, capture.truncated, capture.reported)
	}
}

// childStderrDiagnostic stands in for a Codex diagnostic that carries a
// provider credential, which must never reach the Connector log.
const childStderrDiagnostic = "Authorization: Bearer sk-provider-secret\n"

func TestStartDoesNotForwardAppServerStderrContents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}
	script := fakeCodexStderrLeak(t, childStderrDiagnostic)
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	client, err := Start(ctx, StartOptions{
		Binary: script, ExpectedVersion: "0.147.0", ConnectorVersion: "test",
		InitializeTimeout: 5 * time.Second, Stderr: &output,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = client.Wait()
	cancel()

	report := output.String()
	if strings.Contains(report, "provider-secret") || strings.Contains(report, "Authorization") {
		t.Fatalf("child stderr leaked through Start: %q", report)
	}
	want := fmt.Sprintf("codex app-server stderr suppressed (bytes=%d)\n", len(childStderrDiagnostic))
	if report != want {
		t.Fatalf("stderr report = %q, want %q", report, want)
	}
}

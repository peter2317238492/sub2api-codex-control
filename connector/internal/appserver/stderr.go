package appserver

import (
	"fmt"
	"io"
	"sync"
)

const maxObservedStderrBytes uint64 = 64 << 10

// childStderrCapture drains app-server stderr without retaining or forwarding
// its arbitrary contents. Only bounded metadata is emitted once the child has
// exited, so prompts, credentials, and provider diagnostics cannot enter the
// Connector's routine logs.
type childStderrCapture struct {
	mu          sync.Mutex
	destination io.Writer
	observed    uint64
	truncated   bool
	reported    bool
}

func newChildStderrCapture(destination io.Writer) *childStderrCapture {
	return &childStderrCapture{destination: destination}
}

func (capture *childStderrCapture) Write(data []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()

	remaining := maxObservedStderrBytes - capture.observed
	if uint64(len(data)) > remaining {
		capture.observed = maxObservedStderrBytes
		capture.truncated = true
	} else {
		capture.observed += uint64(len(data))
	}
	return len(data), nil
}

func (capture *childStderrCapture) report() {
	capture.mu.Lock()
	if capture.reported || capture.observed == 0 {
		capture.mu.Unlock()
		return
	}
	capture.reported = true
	destination := capture.destination
	observed := capture.observed
	truncated := capture.truncated
	capture.mu.Unlock()

	if destination == nil {
		return
	}
	if truncated {
		_, _ = fmt.Fprintf(destination, "codex app-server stderr suppressed (bytes>=%d)\n", observed)
		return
	}
	_, _ = fmt.Fprintf(destination, "codex app-server stderr suppressed (bytes=%d)\n", observed)
}

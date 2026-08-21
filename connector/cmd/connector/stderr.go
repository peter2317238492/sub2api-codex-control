package main

import (
	"fmt"
	"io"
	"sync"
)

// stderrSink writes connector diagnostics to the console and, once a log file
// is attached, duplicates them into that private state file. The console write
// is never skipped and its result is what callers observe, because a scheduled
// task has no console: a failing console handle must not suppress the log, and
// a failing log must not change what an attached console receives.
type stderrSink struct {
	mu      sync.Mutex
	console io.Writer
	file    io.WriteCloser
	failed  bool
}

func newStderrSink(console io.Writer) *stderrSink {
	return &stderrSink{console: console}
}

func (s *stderrSink) Attach(file io.WriteCloser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.file = file
}

func (s *stderrSink) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	written, err := s.console.Write(data)
	if s.file == nil {
		return written, err
	}
	if _, fileErr := s.file.Write(data); fileErr != nil && !s.failed {
		s.failed = true
		_, _ = fmt.Fprintln(s.console, "connector: log file write failed (details suppressed)")
	}
	return written, err
}

func (s *stderrSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	file := s.file
	s.file = nil
	if file == nil {
		return nil
	}
	return file.Close()
}

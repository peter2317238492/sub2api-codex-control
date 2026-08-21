package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/wspath"
)

const (
	logRotateBytes   int64 = 4 << 20
	logFileSuffix          = ".log"
	logRotatedSuffix       = ".1"
)

var logPathMapper = wspath.NewMapper()

// LogFile duplicates connector diagnostics into a private state file for runs
// that have no console. It is rotated at a fixed size and keeps one previous
// generation, so an unattended run cannot grow local state without bound.
type LogFile struct {
	mu      sync.Mutex
	path    string
	rotated string
	limit   int64
	file    *os.File
	written int64
	closed  bool
}

// OpenLogFile opens the connector log file named by path inside stateDir. The
// name must end in .log and resolve to a direct child of stateDir, so it can
// neither escape the state directory nor alias another state object.
func OpenLogFile(stateDir, path string) (*LogFile, error) {
	return openLogFile(stateDir, path, logRotateBytes)
}

func openLogFile(stateDir, path string, limit int64) (*LogFile, error) {
	resolved, err := resolveLogPath(stateDir, path)
	if err != nil {
		return nil, err
	}
	log := &LogFile{path: resolved, rotated: resolved + logRotatedSuffix, limit: limit}
	if err := log.reopen(); err != nil {
		return nil, err
	}
	return log, nil
}

func resolveLogPath(stateDir, path string) (string, error) {
	if !filepath.IsAbs(stateDir) {
		return "", errors.New("log file requires an absolute state directory")
	}
	if strings.TrimSpace(path) == "" {
		return "", errors.New("log file path is empty")
	}
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(stateDir, resolved)
	}
	resolved = filepath.Clean(resolved)
	if !logPathMapper.SamePath(filepath.Dir(resolved), filepath.Clean(stateDir)) {
		return "", fmt.Errorf("log file %s must name a file directly inside the state directory", path)
	}
	name := filepath.Base(resolved)
	if !strings.HasSuffix(name, logFileSuffix) || len(name) == len(logFileSuffix) {
		return "", fmt.Errorf("log file %s must end in %s", path, logFileSuffix)
	}
	return resolved, nil
}

func (l *LogFile) reopen() error {
	if err := securefile.EnsureDir(filepath.Dir(l.path)); err != nil {
		return err
	}
	file, err := securefile.CreatePrivateFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND)
	if err != nil {
		return fmt.Errorf("create connector log file: %w", err)
	}
	info, err := securefile.ValidateOwnerAndACL(file, false)
	if err != nil {
		_ = file.Close()
		return err
	}
	// StatPrivateFile applies the platform's complete private-state-file rules
	// to the path, and SameFile binds that verdict to the handle already held,
	// so an object swapped in between the two lookups is never adopted.
	pathInfo, err := securefile.StatPrivateFile(l.path)
	if err != nil {
		_ = file.Close()
		return err
	}
	if !os.SameFile(info, pathInfo) {
		_ = file.Close()
		return errors.New("connector log file path changed during validation")
	}
	l.file = file
	l.written = info.Size()
	return nil
}

func (l *LogFile) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.file == nil {
		return 0, errors.New("connector log file is closed")
	}
	if l.written > 0 && l.written+int64(len(data)) > l.limit {
		if err := l.rotate(); err != nil {
			return 0, l.failedRotation(err)
		}
	}
	written, err := l.file.Write(data)
	l.written += int64(written)
	if err != nil {
		return written, err
	}
	// A scheduled task is normally stopped by termination rather than by a
	// graceful exit, so an unsynced tail is exactly the part an operator needs.
	return written, l.file.Sync()
}

// failedRotation retires the sink unless another process is merely holding a
// generation of the log open. In that case the cap stays in force -- the
// record that triggered the rotation is dropped rather than written past it --
// and the current generation is reopened so the next write retries. An
// operator reading the log then costs diagnostics for the length of their read
// instead of for the life of an unattended run, which has no other channel.
func (l *LogFile) failedRotation(err error) error {
	if !rotationBlocked(err) {
		l.closed = true
		return err
	}
	if reopenErr := l.reopen(); reopenErr != nil {
		l.closed = true
		return errors.Join(err, reopenErr)
	}
	return err
}

func (l *LogFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	file := l.file
	l.file = nil
	l.closed = true
	if file == nil {
		return nil
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close connector log file: %w", err)
	}
	return nil
}

func (l *LogFile) rotate() error {
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close connector log file: %w", err)
	}
	l.file = nil
	l.written = 0
	if err := os.Remove(l.rotated); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove rotated connector log file: %w", err)
	}
	if err := os.Rename(l.path, l.rotated); err != nil {
		return fmt.Errorf("rotate connector log file: %w", err)
	}
	return l.reopen()
}

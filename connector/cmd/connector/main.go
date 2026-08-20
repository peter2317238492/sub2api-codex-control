package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/auth"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/config"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/identity"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/pairing"
	connectorRuntime "github.com/peter2317238492/sub2api-codex-control/connector/internal/runtime"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/statelock"
)

var errStateLockRelease = errors.New("connector state lock release failed")

func main() {
	configPath := flag.String("config", "connector.json", "path to the connector JSON config")
	pairOnly := flag.Bool("pair-only", false, "pair this device and exit")
	logFile := flag.String("log-file", "", "also write connector diagnostics to this rotating log file inside state_dir")
	showVersion := flag.Bool("version", false, "print connector version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(connectorBinaryVersion())
		return
	}
	stderr := newStderrSink(os.Stderr)
	if err := run(*configPath, *pairOnly, *logFile, stderr); shouldReportTerminalError(err) {
		reportTerminalError(stderr, err)
		_ = stderr.Close()
		os.Exit(1)
	}
	if err := stderr.Close(); err != nil {
		reportTerminalError(stderr, err)
		os.Exit(1)
	}
}

func shouldReportTerminalError(err error) bool {
	return err != nil && (!errors.Is(err, context.Canceled) || errors.Is(err, errStateLockRelease))
}

func joinStateLockReleaseError(runErr, releaseErr error) error {
	if releaseErr == nil {
		return runErr
	}
	return errors.Join(runErr, fmt.Errorf("%w: %w", errStateLockRelease, releaseErr))
}

// reportPairingCodePath names only the private file that holds the pairing
// code, so neither the console nor the log file ever carries the code itself.
func reportPairingCodePath(destination io.Writer, path string) {
	_, _ = fmt.Fprintf(destination, "Pairing code written to %s\n", path)
}

func reportTerminalError(destination io.Writer, err error) {
	if errors.Is(err, statelock.ErrInUse) {
		_, _ = fmt.Fprintln(destination, "connector: state directory is already in use")
		return
	}
	// A misconfigured state volume is an install mistake, not a runtime fault,
	// and under a scheduled task there is no console to investigate it from.
	// This fixed string names the cause without describing the environment.
	if errors.Is(err, securefile.ErrUnsupportedVolume) {
		_, _ = fmt.Fprintln(destination,
			"connector: state_dir is on a volume that cannot record access control lists; choose an NTFS volume")
		return
	}
	if errors.Is(err, securefile.ErrUntrustedLocation) {
		_, _ = fmt.Fprintln(destination,
			"connector: state_dir or a directory above it is reachable by another principal; choose a private location")
		return
	}
	_, _ = fmt.Fprintln(destination, "connector: terminated with an error (details suppressed)")
}

func run(configPath string, pairOnly bool, logPath string, stderr *stderrSink) (resultErr error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	stateLock, err := statelock.Acquire(cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = joinStateLockReleaseError(resultErr, stateLock.Release())
	}()
	if logPath != "" {
		logFile, logErr := connectorRuntime.OpenLogFile(cfg.StateDir, logPath)
		if logErr != nil {
			return logErr
		}
		stderr.Attach(logFile)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pairingClient := &pairing.Client{
		StartURL: cfg.PairingURL, PollInterval: cfg.PairingPollInterval.Value(),
	}
	var deviceIdentity *identity.Identity
	credentials, err := pairing.LoadOrPairWithCodeFilePrepared(
		ctx,
		filepath.Join(cfg.StateDir, "device-credentials.json"),
		filepath.Join(cfg.StateDir, "pairing-code.json"),
		pairingClient,
		func() (pairing.StartRequest, error) {
			preparedIdentity, prepareErr := identity.LoadOrCreate(
				filepath.Join(cfg.StateDir, "device-identity.json"),
			)
			if prepareErr != nil {
				return pairing.StartRequest{}, prepareErr
			}
			deviceIdentity = preparedIdentity
			pairingClient.Sign = preparedIdentity.Sign
			return pairing.StartRequest{
				PublicKey: preparedIdentity.PublicKeyString(), DisplayName: cfg.DisplayName,
				ConnectorVersion: config.DefaultConnectorVersion, CodexVersion: cfg.CodexVersion,
				WorkspaceRoots: append([]string(nil), cfg.RemoteWorkspaceRoots...),
			}, nil
		}, func(path string) {
			reportPairingCodePath(stderr, path)
		})
	if err != nil {
		return err
	}
	if pairOnly {
		_, _ = fmt.Fprintf(stderr, "Device paired: %s\n", credentials.DeviceID)
		return nil
	}
	if deviceIdentity == nil {
		return errors.New("device identity was not prepared")
	}
	tokenSource := &auth.HTTPTokenSource{
		URL: cfg.TokenURL, Credentials: credentials, Identity: deviceIdentity,
	}
	return connectorRuntime.Run(ctx, connectorRuntime.Options{
		Config: cfg, Identity: deviceIdentity, Credentials: credentials,
		TokenSource: tokenSource, Stderr: stderr,
	})
}

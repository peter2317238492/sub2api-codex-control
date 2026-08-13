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
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/statelock"
)

var errStateLockRelease = errors.New("connector state lock release failed")

func main() {
	configPath := flag.String("config", "connector.json", "path to the connector JSON config")
	pairOnly := flag.Bool("pair-only", false, "pair this device and exit")
	showVersion := flag.Bool("version", false, "print connector version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(connectorBinaryVersion())
		return
	}
	if err := run(*configPath, *pairOnly); shouldReportTerminalError(err) {
		reportTerminalError(os.Stderr, err)
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

func reportTerminalError(destination io.Writer, err error) {
	if errors.Is(err, statelock.ErrInUse) {
		_, _ = fmt.Fprintln(destination, "connector: state directory is already in use")
		return
	}
	_, _ = fmt.Fprintln(destination, "connector: terminated with an error (details suppressed)")
}

func run(configPath string, pairOnly bool) (resultErr error) {
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
				WorkspaceRoots: append([]string(nil), cfg.WorkspaceRoots...),
			}, nil
		}, func(path string) {
			fmt.Fprintf(os.Stderr, "Pairing code written to %s\n", path)
		})
	if err != nil {
		return err
	}
	if pairOnly {
		fmt.Fprintf(os.Stderr, "Device paired: %s\n", credentials.DeviceID)
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
		TokenSource: tokenSource, Stderr: os.Stderr,
	})
}

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var validDelta = json.RawMessage(`{
	"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":"hello"
}`)

func TestNotificationSpoolFailureCancelsSession(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	failure := newSessionFailure(cancel)
	spoolFailure := errors.New("spool is full")
	handler := newNotificationHandler(
		ctx,
		func(context.Context, string, any) error { return spoolFailure },
		func(string, json.RawMessage) (bool, error) { return true, nil },
		failure.Fail,
	)
	handler.Handle("item/agentMessage/delta", validDelta)
	if !errors.Is(failure.Err(), spoolFailure) {
		t.Fatalf("session failure = %v", failure.Err())
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("spool failure did not cancel the app-server session")
	}
}

func TestNotificationRateLimitFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	failure := newSessionFailure(cancel)
	emitted := 0
	handler := newNotificationHandler(
		ctx,
		func(context.Context, string, any) error {
			emitted++
			return nil
		},
		func(string, json.RawMessage) (bool, error) { return true, nil },
		failure.Fail,
	)
	fixedNow := time.Now()
	handler.limiter = newTokenBucket(notificationRatePerSecond, notificationBurst, func() time.Time { return fixedNow })
	for index := 0; index < notificationBurst+1; index++ {
		handler.Handle("item/agentMessage/delta", validDelta)
	}
	if !errors.Is(failure.Err(), errNotificationRateExceeded) {
		t.Fatalf("session failure = %v", failure.Err())
	}
	if emitted != notificationBurst {
		t.Fatalf("emitted notifications = %d, want %d", emitted, notificationBurst)
	}
}

func TestNotificationBucketRefillsAtBoundedRate(t *testing.T) {
	now := time.Now()
	limiter := newTokenBucket(4, 4, func() time.Time { return now })
	for index := 0; index < 4; index++ {
		if !limiter.Allow() {
			t.Fatalf("initial token %d was denied", index)
		}
	}
	if limiter.Allow() {
		t.Fatal("empty token bucket admitted an event")
	}
	now = now.Add(500 * time.Millisecond)
	for index := 0; index < 2; index++ {
		if !limiter.Allow() {
			t.Fatalf("refilled token %d was denied", index)
		}
	}
	if limiter.Allow() {
		t.Fatal("token bucket refilled faster than configured")
	}
}

func TestNotificationProjectionFailureCancelsWithoutEmitting(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	failure := newSessionFailure(cancel)
	emitted := 0
	handler := newNotificationHandler(
		ctx,
		func(context.Context, string, any) error {
			emitted++
			return nil
		},
		func(string, json.RawMessage) (bool, error) { return true, nil },
		failure.Fail,
	)
	handler.Handle("item/agentMessage/delta", json.RawMessage(`{"delta":`))
	if failure.Err() == nil || !strings.Contains(failure.Err().Error(), "project app-server notification") {
		t.Fatalf("session failure = %v", failure.Err())
	}
	if emitted != 0 {
		t.Fatalf("invalid event emitted %d times", emitted)
	}
}

func TestSessionFailureRecordsOnlyFirstCause(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	failure := newSessionFailure(cancel)
	first := errors.New("first")
	second := errors.New("second")
	var wait sync.WaitGroup
	for _, err := range []error{first, second} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			failure.Fail(err)
		}()
	}
	wait.Wait()
	if err := failure.Err(); !errors.Is(err, first) && !errors.Is(err, second) {
		t.Fatalf("recorded failure = %v", err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("session was not canceled")
	}
}

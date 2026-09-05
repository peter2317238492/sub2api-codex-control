package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

const (
	notificationRatePerSecond = 64
	notificationBurst         = 128
)

var errNotificationRateExceeded = errors.New("app-server notification rate exceeded")

type notificationEmitter func(context.Context, string, any) error
type notificationObserver func(string, json.RawMessage) (bool, error)

type notificationHandler struct {
	ctx      context.Context
	emit     notificationEmitter
	observe  notificationObserver
	canary   func(string, json.RawMessage) error
	fail     func(error)
	limiter  *tokenBucket
	failOnce sync.Once
}

func newNotificationHandler(
	ctx context.Context,
	emit notificationEmitter,
	observe notificationObserver,
	fail func(error),
) *notificationHandler {
	return &notificationHandler{
		ctx: ctx, emit: emit, observe: observe, fail: fail,
		limiter: newTokenBucket(notificationRatePerSecond, notificationBurst, time.Now),
	}
}

func (h *notificationHandler) Handle(method string, params json.RawMessage) {
	if h.ctx.Err() != nil {
		return
	}
	if h.canary != nil {
		if err := h.canary(method, params); err != nil {
			h.failSession(err)
			return
		}
	}
	if !policy.EventAllowed(method) {
		return
	}
	if !h.limiter.Allow() {
		h.failSession(errNotificationRateExceeded)
		return
	}
	projected, allowed, err := policy.ProjectEvent(method, params)
	if err != nil {
		h.failSession(fmt.Errorf("project app-server notification %s: %w", method, err))
		return
	}
	if !allowed {
		return
	}
	observed, err := h.observe(method, projected)
	if err != nil {
		h.failSession(fmt.Errorf("observe app-server notification %s: %w", method, err))
		return
	}
	if !observed {
		return
	}
	if err := h.emit(h.ctx, protocol.TypeEvent, map[string]any{"method": method, "params": projected}); err != nil {
		h.failSession(fmt.Errorf("persist projected app-server notification %s: %w", method, err))
	}
}

func (h *notificationHandler) failSession(err error) {
	if h.fail == nil || err == nil {
		return
	}
	h.failOnce.Do(func() { h.fail(err) })
}

type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

func newTokenBucket(rate, capacity int, now func() time.Time) *tokenBucket {
	if rate <= 0 || capacity <= 0 || capacity < rate {
		panic("invalid token bucket limits")
	}
	if now == nil {
		now = time.Now
	}
	current := now()
	return &tokenBucket{
		rate: float64(rate), capacity: float64(capacity), tokens: float64(capacity),
		last: current, now: now,
	}
}

func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if now.After(b.last) {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens = min(b.capacity, b.tokens+elapsed*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type sessionFailure struct {
	mu     sync.Mutex
	once   sync.Once
	err    error
	cancel context.CancelFunc
}

func newSessionFailure(cancel context.CancelFunc) *sessionFailure {
	return &sessionFailure{cancel: cancel}
}

func (f *sessionFailure) Fail(err error) {
	if err == nil {
		return
	}
	f.once.Do(func() {
		f.mu.Lock()
		f.err = err
		f.mu.Unlock()
		f.cancel()
	})
}

func (f *sessionFailure) Err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

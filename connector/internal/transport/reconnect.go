package transport

import (
	"errors"
	"time"

	"github.com/coder/websocket"
)

const maxRapidNetworkFailures = 8

var ErrReconnectCircuit = errors.New("device transport reconnect circuit is open")

type reconnectPolicy struct {
	minimum       time.Duration
	maximum       time.Duration
	stableAfter   time.Duration
	nextDelay     time.Duration
	rapidFailures int
}

func newReconnectPolicy(minimum, maximum, stableAfter time.Duration) reconnectPolicy {
	return reconnectPolicy{
		minimum: minimum, maximum: maximum, stableAfter: stableAfter, nextDelay: minimum,
	}
}

func (policy *reconnectPolicy) afterFailure(connectedFor time.Duration) (time.Duration, error) {
	if connectedFor >= policy.stableAfter {
		policy.rapidFailures = 0
		policy.nextDelay = policy.minimum
	}
	policy.rapidFailures++
	if policy.rapidFailures > maxRapidNetworkFailures {
		return 0, ErrReconnectCircuit
	}

	delay := policy.nextDelay
	if policy.nextDelay >= policy.maximum/2 {
		policy.nextDelay = policy.maximum
	} else {
		policy.nextDelay *= 2
	}
	return delay, nil
}

type retryableOperationError struct{ cause error }

func (failure *retryableOperationError) Error() string { return failure.cause.Error() }
func (failure *retryableOperationError) Unwrap() error { return failure.cause }

func retryableOperation(err error) error {
	if err == nil {
		return nil
	}
	return &retryableOperationError{cause: err}
}

func connectionIOError(err error) error {
	if err == nil {
		return nil
	}
	switch websocket.CloseStatus(err) {
	case websocket.StatusProtocolError,
		websocket.StatusUnsupportedData,
		websocket.StatusInvalidFramePayloadData,
		websocket.StatusPolicyViolation,
		websocket.StatusMessageTooBig,
		websocket.StatusMandatoryExtension:
		return err
	default:
		return retryableOperation(err)
	}
}

type connectionFailure struct {
	cause        error
	retryable    bool
	connectedFor time.Duration
	reason       ReconnectReason
}

func (failure *connectionFailure) Error() string { return failure.cause.Error() }
func (failure *connectionFailure) Unwrap() error { return failure.cause }

func classifyConnectionFailure(err error, connectedFor time.Duration) error {
	return classifyConnectionFailureWithReason(err, connectedFor, ReconnectConnectionIO)
}

func classifyConnectionFailureWithReason(err error, connectedFor time.Duration, reason ReconnectReason) error {
	if err == nil {
		err = errors.New("device transport stopped without an error")
	}
	var retryable *retryableOperationError
	return &connectionFailure{
		cause:        err,
		retryable:    errors.Is(err, ErrRefreshToken) || errors.As(err, &retryable),
		connectedFor: connectedFor,
		reason:       reason,
	}
}

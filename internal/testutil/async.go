package testutil

import (
	"testing"
	"time"
)

// WaitTimeout bounds asynchronous operations in tests.
const WaitTimeout = 5 * time.Second

// Receive waits for one value, reporting a test error on timeout.
func Receive[T any](t *testing.T, event <-chan T, name string) (T, bool) {
	t.Helper()
	select {
	case value := <-event:
		return value, true
	case <-time.After(WaitTimeout):
		t.Errorf("timed out waiting for %s", name)
		var zero T
		return zero, false
	}
}

// WaitForEvent waits for an event, reporting a test error on timeout.
func WaitForEvent(t *testing.T, event <-chan struct{}, name string) bool {
	t.Helper()
	_, ok := Receive(t, event, name)
	return ok
}

// AsyncResult holds the completion and error of an asynchronous operation.
type AsyncResult struct {
	done chan struct{}
	err  error
}

// RunAsync runs fn in a goroutine and records its result.
func RunAsync(fn func() error) *AsyncResult {
	result := &AsyncResult{done: make(chan struct{})}
	go func() {
		result.err = fn()
		close(result.done)
	}()
	return result
}

// Done is closed when the operation completes.
func (r *AsyncResult) Done() <-chan struct{} {
	return r.done
}

// Err waits for completion and returns the operation's error.
func (r *AsyncResult) Err() error {
	<-r.done
	return r.err
}

// WaitForAsyncStop waits for an asynchronous operation to finish.
func WaitForAsyncStop(t *testing.T, result *AsyncResult, name string) bool {
	t.Helper()
	return WaitForEvent(t, result.Done(), name+" to stop")
}

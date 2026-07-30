package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
)

func TestPreparedStreamCommitCancellationUnblocksSetupWrite(t *testing.T) {
	opened := newCancellationStream()
	session := readyTestSession(t, opened)
	prepared, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	addActiveStreamSentinel(session)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan preparedCommitResult, 1)
	go func() {
		conn, err := prepared.Commit(ctx, []byte("opaque-setup"), false)
		result <- preparedCommitResult{conn: conn, err: err}
	}()
	awaitPreparedSignal(t, opened.writeStarted, "setup write")
	cancel()

	select {
	case got := <-result:
		assertCanceledCommit(t, got)
	case <-time.After(250 * time.Millisecond):
		opened.releaseWrite()
		got := <-result
		if got.conn != nil {
			_ = got.conn.Close()
		}
		t.Fatal("Commit remained blocked after context cancellation")
	}
	opened.assertCanceledAndClosedOnce(t)
	assertActiveStreamSentinel(t, session)
	if err := prepared.Close(); err != nil {
		t.Fatalf("Close after canceled Commit: %v", err)
	}
	opened.assertCanceledAndClosedOnce(t)
	assertActiveStreamSentinel(t, session)
}

func TestPreparedStreamCommitChecksCancellationAfterSetupWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opened := newCancellationStream()
	opened.cancelOnWrite = cancel
	session := readyTestSession(t, opened)
	prepared, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	addActiveStreamSentinel(session)

	conn, err := prepared.Commit(ctx, []byte("opaque-setup"), false)
	assertCanceledCommit(t, preparedCommitResult{conn: conn, err: err})
	opened.assertCanceledAndClosedOnce(t)
	assertActiveStreamSentinel(t, session)
}

func TestPreparedStreamCommitCancellationAfterStoppedResetAbortsStream(t *testing.T) {
	opened := &postStopCancellationStream{}
	session := readyTestSession(t, opened)
	prepared, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	addActiveStreamSentinel(session)

	ctx := newPostStopCancellationContext()
	t.Cleanup(ctx.cancelAndRelease)
	result := make(chan preparedCommitResult, 1)
	go func() {
		conn, err := prepared.Commit(ctx, []byte("opaque-setup"), true)
		result <- preparedCommitResult{conn: conn, err: err}
	}()
	awaitPreparedSignal(t, ctx.errObserved, "post-stop context error check")
	ctx.cancelAndRelease()

	select {
	case got := <-result:
		assertCanceledCommit(t, got)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Commit remained blocked after post-stop cancellation")
	}
	opened.assertCalls(t, "Write", "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
	assertActiveStreamSentinel(t, session)
}

type preparedCommitResult struct {
	conn net.Conn
	err  error
}

func assertCanceledCommit(t *testing.T, got preparedCommitResult) {
	t.Helper()
	if got.conn != nil || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("Commit = (%v, %v), want (nil, context.Canceled)", got.conn, got.err)
	}
}

func addActiveStreamSentinel(session *Session) {
	session.mu.Lock()
	session.activeConns++
	session.mu.Unlock()
}

func assertActiveStreamSentinel(t *testing.T, session *Session) {
	t.Helper()
	session.mu.Lock()
	active := session.activeConns
	session.mu.Unlock()
	if active != 1 {
		t.Fatalf("active streams = %d, want sentinel-only 1", active)
	}
}

func awaitPreparedSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

type cancellationStream struct {
	mu               sync.Mutex
	writeStarted     chan struct{}
	writeRelease     chan struct{}
	writeStartedOnce sync.Once
	writeReleaseOnce sync.Once
	cancelOnWrite    context.CancelFunc
	writeCanceled    bool
	readCanceled     bool
	deadlineCalls    int
	closeCalls       int
}

func newCancellationStream() *cancellationStream {
	return &cancellationStream{writeStarted: make(chan struct{}), writeRelease: make(chan struct{})}
}

func (*cancellationStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *cancellationStream) Write(p []byte) (int, error) {
	s.writeStartedOnce.Do(func() { close(s.writeStarted) })
	if s.cancelOnWrite != nil {
		s.cancelOnWrite()
		return len(p), nil
	}
	<-s.writeRelease
	s.mu.Lock()
	canceled := s.writeCanceled
	s.mu.Unlock()
	if canceled {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (s *cancellationStream) Close() error {
	s.mu.Lock()
	s.closeCalls++
	s.mu.Unlock()
	s.releaseWrite()
	return nil
}

func (*cancellationStream) SetDeadline(time.Time) error     { return nil }
func (*cancellationStream) SetReadDeadline(time.Time) error { return nil }
func (s *cancellationStream) SetWriteDeadline(time.Time) error {
	s.mu.Lock()
	s.deadlineCalls++
	s.mu.Unlock()
	return nil
}

func (s *cancellationStream) CancelRead(quic.StreamErrorCode) {
	s.mu.Lock()
	s.readCanceled = true
	s.mu.Unlock()
}

func (s *cancellationStream) CancelWrite(quic.StreamErrorCode) {
	s.mu.Lock()
	s.writeCanceled = true
	s.mu.Unlock()
	s.releaseWrite()
}

func (s *cancellationStream) releaseWrite() {
	s.writeReleaseOnce.Do(func() { close(s.writeRelease) })
}

func (s *cancellationStream) assertCanceledAndClosedOnce(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	writeCanceled := s.writeCanceled
	readCanceled := s.readCanceled
	deadlineCalls := s.deadlineCalls
	closeCalls := s.closeCalls
	s.mu.Unlock()
	if !writeCanceled || !readCanceled {
		t.Fatalf("canceled directions = write:%v read:%v, want both", writeCanceled, readCanceled)
	}
	if deadlineCalls == 0 {
		t.Fatal("setup cancellation did not set a write deadline")
	}
	if closeCalls != 1 {
		t.Fatalf("stream Close calls = %d, want 1", closeCalls)
	}
}

type postStopCancellationContext struct {
	mu          sync.Mutex
	err         error
	done        chan struct{}
	errObserved chan struct{}
	allowErr    chan struct{}
	errOnce     sync.Once
	cancelOnce  sync.Once
	releaseOnce sync.Once
}

func newPostStopCancellationContext() *postStopCancellationContext {
	return &postStopCancellationContext{
		done:        make(chan struct{}),
		errObserved: make(chan struct{}),
		allowErr:    make(chan struct{}),
	}
}

func (*postStopCancellationContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *postStopCancellationContext) Done() <-chan struct{}     { return c.done }
func (c *postStopCancellationContext) Err() error {
	c.errOnce.Do(func() {
		close(c.errObserved)
		<-c.allowErr
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
func (*postStopCancellationContext) Value(any) any { return nil }
func (c *postStopCancellationContext) cancelAndRelease() {
	c.cancelOnce.Do(func() {
		c.mu.Lock()
		c.err = context.Canceled
		c.mu.Unlock()
		close(c.done)
	})
	c.releaseOnce.Do(func() { close(c.allowErr) })
}

type postStopCancellationStream struct {
	mu    sync.Mutex
	calls []string
}

func (*postStopCancellationStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *postStopCancellationStream) Write(payload []byte) (int, error) {
	s.record("Write")
	return len(payload), nil
}

func (s *postStopCancellationStream) Close() error {
	s.record("Close")
	return nil
}
func (*postStopCancellationStream) SetDeadline(time.Time) error     { return nil }
func (*postStopCancellationStream) SetReadDeadline(time.Time) error { return nil }
func (s *postStopCancellationStream) SetWriteDeadline(time.Time) error {
	s.record("SetWriteDeadline")
	return nil
}

func (s *postStopCancellationStream) CancelRead(quic.StreamErrorCode) {
	s.record("CancelRead(0)")
}

func (s *postStopCancellationStream) CancelWrite(quic.StreamErrorCode) {
	s.record("CancelWrite(0)")
}

func (s *postStopCancellationStream) record(call string) {
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
}

func (s *postStopCancellationStream) assertCalls(t *testing.T, want ...string) {
	t.Helper()
	s.mu.Lock()
	got := append([]string(nil), s.calls...)
	s.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	}
}

var (
	_ context.Context = (*postStopCancellationContext)(nil)
	_ stream          = (*cancellationStream)(nil)
	_ stream          = (*postStopCancellationStream)(nil)
)

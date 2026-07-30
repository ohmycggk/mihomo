package quic

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
)

func TestPreparedStreamCommitsOpaqueSetupAndFinishesWrite(t *testing.T) {
	opened := &fakeStream{maxWrite: 2}
	session := readyTestSession(t, opened)

	prepared, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	setup := []byte{0x00, 0xff, 0x10, 0x20, 0x30}
	conn, err := prepared.Commit(context.Background(), setup, true)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := opened.Bytes(); !bytes.Equal(got, setup) {
		t.Fatalf("written setup = %x, want %x", got, setup)
	}
	if got := opened.CloseCalls(); got != 1 {
		t.Fatalf("stream Close calls after Commit = %d, want 1", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("committed conn Close: %v", err)
	}
	if session.activeConns != 0 {
		t.Fatalf("active streams after Close = %d, want 0", session.activeConns)
	}
}

func TestPreparedStreamCanKeepWriteSideOpen(t *testing.T) {
	opened := &fakeStream{}
	session := readyTestSession(t, opened)

	prepared, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	conn, err := prepared.Commit(context.Background(), []byte("setup"), false)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := opened.CloseCalls(); got != 0 {
		t.Fatalf("stream Close calls after Commit = %d, want 0", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("committed conn Close: %v", err)
	}
}

func TestStreamConnHalfCloseKeepsOppositeDirectionUsable(t *testing.T) {
	t.Run("close write preserves read", func(t *testing.T) {
		opened := &fakeStream{}
		releases := 0
		conn := &streamConn{stream: opened, onClose: func() { releases++ }}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if opened.CloseCalls() != 1 || opened.ReadCanceled() {
			t.Fatalf("close calls=%d read canceled=%v", opened.CloseCalls(), opened.ReadCanceled())
		}
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("Read = %v, want EOF", err)
		}
		if releases != 0 {
			t.Fatalf("stream released by half-close: %d", releases)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if releases != 1 {
			t.Fatalf("stream releases = %d, want 1", releases)
		}
	})

	t.Run("close read preserves write", func(t *testing.T) {
		opened := &fakeStream{}
		conn := &streamConn{stream: opened}
		if err := conn.CloseRead(); err != nil {
			t.Fatal(err)
		}
		if err := conn.CloseRead(); err != nil {
			t.Fatal(err)
		}
		if !opened.ReadCanceled() || opened.CloseCalls() != 0 {
			t.Fatalf("read canceled=%v close calls=%d", opened.ReadCanceled(), opened.CloseCalls())
		}
		if _, err := conn.Write([]byte("after-close-read")); err != nil {
			t.Fatal(err)
		}
		if got := opened.Bytes(); !bytes.Equal(got, []byte("after-close-read")) {
			t.Fatalf("written = %q", got)
		}
	})
}

func TestPreparedStreamCloseAbortsExactlyOnce(t *testing.T) {
	opened := &fakeStream{}
	session := readyTestSession(t, opened)

	prepared, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := opened.CloseCalls(); got != 1 {
		t.Fatalf("stream Close calls = %d, want 1", got)
	}
	if !opened.ReadCanceled() || !opened.WriteCanceled() {
		t.Fatal("prepared Close did not cancel both stream directions")
	}
	if session.activeConns != 0 {
		t.Fatalf("active streams after abort = %d, want 0", session.activeConns)
	}
}

func readyTestSession(t *testing.T, opened stream) *Session {
	t.Helper()
	session := NewSession(&QUICConfig{Addr: "127.0.0.1:1"})
	session.openStream = func(context.Context) (stream, error) { return opened, nil }
	close(session.ready)
	return session
}

type fakeStream struct {
	mu            sync.Mutex
	written       bytes.Buffer
	maxWrite      int
	closeCalls    int
	readCanceled  bool
	writeCanceled bool
}

func (s *fakeStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *fakeStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxWrite > 0 && len(p) > s.maxWrite {
		p = p[:s.maxWrite]
	}
	return s.written.Write(p)
}

func (s *fakeStream) Close() error {
	s.mu.Lock()
	s.closeCalls++
	s.mu.Unlock()
	return nil
}

func (s *fakeStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeStream) SetWriteDeadline(time.Time) error { return nil }

func (s *fakeStream) CancelRead(quic.StreamErrorCode) {
	s.mu.Lock()
	s.readCanceled = true
	s.mu.Unlock()
}

func (s *fakeStream) CancelWrite(quic.StreamErrorCode) {
	s.mu.Lock()
	s.writeCanceled = true
	s.mu.Unlock()
}

func (s *fakeStream) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.written.Bytes())
}

func (s *fakeStream) CloseCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeCalls
}

func (s *fakeStream) ReadCanceled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readCanceled
}

func (s *fakeStream) WriteCanceled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeCanceled
}

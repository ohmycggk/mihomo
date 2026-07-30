package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	nquic "github.com/ohmycggk/nowhere-go/carrier/quic"

	"github.com/metacubex/quic-go"
)

// stream contains only the native QUIC stream primitives used by this backend.
type stream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

// preparedStream is an opened stream that has not yet written opaque setup bytes.
type preparedStream struct {
	session *Session
	stream  stream
	once    sync.Once
}

func (s *Session) PrepareStream(ctx context.Context) (nquic.PreparedStream, error) {
	if err := s.EnsureReady(ctx); err != nil {
		return nil, err
	}
	if s.IsClosed() {
		return nil, errSessionClosed
	}
	opened, err := s.openQUICStream(ctx)
	if err != nil {
		s.maybeFailSession(err)
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if closeErr := abortPreparedStream(opened); closeErr != nil {
			return nil, errors.Join(errSessionClosed, closeErr)
		}
		return nil, errSessionClosed
	}
	s.activeConns++
	s.disarmIdleTimerLocked()
	s.mu.Unlock()
	return &preparedStream{session: s, stream: opened}, nil
}

func (p *preparedStream) Commit(ctx context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		conn net.Conn
		err  error
	)
	p.once.Do(func() {
		if p.stream == nil || p.session == nil {
			err = errSessionClosed
			return
		}
		if p.session.IsClosed() {
			_ = p.abort()
			err = errSessionClosed
			return
		}
		select {
		case <-ctx.Done():
			_ = p.abort()
			err = ctx.Err()
			return
		default:
		}
		if writeErr, reset := writeAllContext(ctx, p.stream, setup); writeErr != nil {
			if reset {
				err = errors.Join(writeErr, p.closeAfterReset())
			} else {
				_ = p.abort()
				if ctxErr := ctx.Err(); ctxErr != nil {
					err = ctxErr
				} else {
					p.session.maybeFailSession(writeErr)
					err = writeErr
				}
			}
			return
		}
		select {
		case <-ctx.Done():
			_ = p.abort()
			err = ctx.Err()
			return
		default:
		}
		if finishWrite {
			if closeErr := p.stream.Close(); closeErr != nil {
				resetPreparedStream(p.stream)
				p.session.ReleaseStream()
				p.session.maybeFailSession(closeErr)
				p.stream = nil
				err = closeErr
				return
			}
		}
		conn = wrapStream(p.session, p.stream)
		p.stream = nil
	})
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (p *preparedStream) Close() error {
	var err error
	p.once.Do(func() {
		err = p.abort()
	})
	return err
}

func (p *preparedStream) abort() error {
	if p.stream == nil {
		return nil
	}
	err := abortPreparedStream(p.stream)
	if p.session != nil {
		p.session.ReleaseStream()
	}
	p.stream = nil
	return err
}

func (p *preparedStream) closeAfterReset() error {
	if p.stream == nil {
		return nil
	}
	err := p.stream.Close()
	if p.session != nil {
		p.session.ReleaseStream()
	}
	p.stream = nil
	return err
}

func writeAllContext(ctx context.Context, opened stream, setup []byte) (error, bool) {
	if ctx.Done() == nil {
		_, err := writeAll(opened, setup)
		return err, false
	}
	resetDone := make(chan struct{})
	var resetDoneOnce sync.Once
	var resetPerformed atomic.Bool
	finishReset := func() { resetDoneOnce.Do(func() { close(resetDone) }) }
	stopReset := contextutils.AfterFunc(ctx, func() {
		resetPerformed.Store(true)
		resetPreparedStream(opened)
		finishReset()
	})
	_, writeErr := writeAll(opened, setup)
	if stopReset() {
		finishReset()
	}
	<-resetDone
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr, resetPerformed.Load()
	}
	return writeErr, false
}

func resetPreparedStream(opened stream) {
	_ = opened.SetWriteDeadline(time.Now())
	opened.CancelWrite(0)
	opened.CancelRead(0)
}

func abortPreparedStream(opened stream) error {
	resetPreparedStream(opened)
	return opened.Close()
}

func writeAll(w io.Writer, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

type streamConn struct {
	stream
	writeMu sync.Mutex
	lAddr   net.Addr
	rAddr   net.Addr
	onClose func()

	readCloseOnce  sync.Once
	readCloseErr   error
	writeCloseOnce sync.Once
	writeCloseErr  error
	closeOnce      sync.Once
	closeErr       error
	releaseOnce    sync.Once
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.stream.Write(p)
}

func (c *streamConn) CloseRead() error {
	c.readCloseOnce.Do(func() {
		c.stream.CancelRead(0)
	})
	return c.readCloseErr
}

func (c *streamConn) CloseWrite() error {
	c.writeCloseOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.writeCloseErr = c.stream.Close()
	})
	return c.writeCloseErr
}

func (c *streamConn) Close() error {
	first := false
	c.closeOnce.Do(func() {
		first = true
		_ = c.stream.SetWriteDeadline(time.Now())
		c.writeMu.Lock()
		readErr := c.CloseRead()
		c.writeCloseOnce.Do(func() {
			c.writeCloseErr = c.stream.Close()
		})
		c.writeMu.Unlock()
		c.closeErr = errors.Join(readErr, c.writeCloseErr)
		c.releaseOnce.Do(func() {
			if c.onClose != nil {
				c.onClose()
			}
		})
	})
	if !first {
		return nil
	}
	return c.closeErr
}

func (c *streamConn) LocalAddr() net.Addr  { return c.lAddr }
func (c *streamConn) RemoteAddr() net.Addr { return c.rAddr }

func wrapStream(session *Session, opened stream) net.Conn {
	var lAddr, rAddr net.Addr
	var onClose func()
	if session != nil {
		onClose = session.ReleaseStream
		if session.conn != nil {
			lAddr = session.conn.LocalAddr()
			rAddr = session.conn.RemoteAddr()
		}
	}
	return &streamConn{stream: opened, lAddr: lAddr, rAddr: rAddr, onClose: onClose}
}

var _ net.Conn = (*streamConn)(nil)

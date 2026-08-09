package quic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/tuic/common"
	nquic "github.com/ohmycggk/nowhere-go/carrier/quic"
	"github.com/ohmycggk/nowhere-go/diagnostic"
	"github.com/ohmycggk/nowhere-go/wire"

	"github.com/metacubex/quic-go"
)

const defaultMaxDatagramSize = 1200

// Session is one handshaked QUIC connection exposing raw stream and DATAGRAM
// primitives. The nowhere-go bundle owns authentication and session identity.
type Session struct {
	cfg *QUICConfig

	conn       *quic.Conn
	openStream func(context.Context) (stream, error)
	cancel     context.CancelFunc
	closed     bool

	receiveDatagram func(context.Context) ([]byte, error)
	sendDatagram    func(context.Context, []byte) error
	localAddr       func() net.Addr
	handshakeInfo   func() (wire.TLSHandshakeInfo, error)
	lifetimeDone    chan struct{}

	mu              sync.Mutex
	dialStarted     bool
	ready           chan struct{}
	readyErr        error
	activeConns     int
	idleTimer       *time.Timer
	idleCloseDelay  time.Duration
	maxDatagramSize int

	closeOnce        sync.Once
	terminalWarnOnce sync.Once
}

func NewSession(cfg *QUICConfig) *Session {
	idleCloseDelay := cfg.IdleCloseDelay
	if idleCloseDelay == 0 {
		if cfg.QUICConfig != nil && cfg.QUICConfig.MaxIdleTimeout > 0 {
			idleCloseDelay = cfg.QUICConfig.MaxIdleTimeout
		} else {
			idleCloseDelay = defaultIdleCloseDelay
		}
	}
	return &Session{
		cfg:             cfg,
		ready:           make(chan struct{}),
		lifetimeDone:    make(chan struct{}),
		idleCloseDelay:  idleCloseDelay,
		maxDatagramSize: defaultMaxDatagramSize,
	}
}

func (s *Session) EnsureReady(ctx context.Context) error {
	select {
	case <-s.ready:
		return s.readyError()
	default:
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.finishReady(errSessionClosed)
		return errSessionClosed
	}
	if s.dialStarted {
		s.mu.Unlock()
		select {
		case <-s.ready:
			return s.readyError()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.dialStarted = true
	dialCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.mu.Unlock()

	go s.run(dialCtx)

	select {
	case <-s.ready:
		return s.readyError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) readyError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readyErr
}

func (s *Session) run(ctx context.Context) {
	defer s.cancel()
	if ctx.Err() != nil || s.IsClosed() {
		s.finishReady(errSessionClosed)
		return
	}
	if err := s.dial(ctx); err != nil {
		s.emit(ctx, diagnostic.LevelError, "quic_session_start_failed", err, "")
		s.finishReady(err)
		s.Close()
		return
	}
	s.emit(ctx, diagnostic.LevelInfo, "quic_session_started", nil, s.cfg.Congestion)
	s.finishReady(nil)
	s.armIdleTimer()

	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		<-conn.Context().Done()
	}
	if !s.IsClosed() {
		s.emitTerminalWarning(ctx, "quic_connection_closed", errConnectionClosed)
	}
	s.failSession(errConnectionClosed)
}

func (s *Session) dial(ctx context.Context) error {
	dialer := s.cfg.Dialer
	if dialer == nil {
		return errors.New("nowhere: nil packet dialer")
	}
	if s.cfg.TLSConfig == nil {
		return errors.New("nowhere: nil tls config")
	}
	tlsConfig := s.cfg.TLSConfig
	if s.cfg.PrepareTLS != nil {
		tlsConfig = tlsConfig.Clone()
		if err := s.cfg.PrepareTLS(ctx, tlsConfig); err != nil {
			return fmt.Errorf("nowhere: prepare tls: %w", err)
		}
	}
	pc, qconn, err := common.DialQuic(ctx, s.cfg.Addr, nil, dialer, tlsConfig, s.cfg.QUICConfig, common.DialQuicOption{})
	if err != nil {
		return fmt.Errorf("nowhere: quic dial: %w", err)
	}
	_ = pc
	if s.cfg.Congestion != "" || s.cfg.CWND != 0 {
		common.SetCongestionController(qconn, s.cfg.Congestion, s.cfg.CWND, "")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = qconn.CloseWithError(quic.ApplicationErrorCode(0), "")
		return errSessionClosed
	}
	s.conn = qconn
	s.mu.Unlock()

	return nil
}

func (s *Session) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	s.mu.Lock()
	conn := s.conn
	closed := s.closed
	handshakeInfo := s.handshakeInfo
	s.mu.Unlock()
	if closed {
		return wire.TLSHandshakeInfo{}, errSessionClosed
	}
	if handshakeInfo != nil {
		return handshakeInfo()
	}
	if conn == nil {
		return wire.TLSHandshakeInfo{}, errSessionClosed
	}
	state := conn.ConnectionState()
	material, err := state.TLS.ExportKeyingMaterial(
		wire.TLSExporterLabel,
		wire.EmptyTLSExporterContext(),
		wire.TLSExporterLen,
	)
	if err != nil {
		return wire.TLSHandshakeInfo{}, err
	}
	if len(material) != wire.TLSExporterLen {
		return wire.TLSHandshakeInfo{}, errors.New("nowhere: invalid QUIC TLS exporter length")
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.TLSHandshakeInfo{
		TLSVersion: state.TLS.Version, NegotiatedALPN: state.TLS.NegotiatedProtocol, Exporter: exporter,
	}, nil
}

func (s *Session) finishReady(err error) {
	s.mu.Lock()
	if s.readyErr == nil && err != nil {
		s.readyErr = err
	} else if err == nil && s.readyErr != nil {
		err = s.readyErr
	}
	select {
	case <-s.ready:
	default:
		close(s.ready)
	}
	s.mu.Unlock()
}

func (s *Session) openQUICStream(ctx context.Context) (stream, error) {
	s.mu.Lock()
	openStream := s.openStream
	conn := s.conn
	closed := s.closed
	s.mu.Unlock()
	if openStream != nil {
		return openStream(ctx)
	}
	if closed || conn == nil {
		return nil, errSessionClosed
	}
	return conn.OpenStreamSync(ctx)
}

func (s *Session) ReleaseStream() {
	s.mu.Lock()
	s.activeConns--
	if s.activeConns < 0 {
		s.activeConns = 0
	}
	s.armIdleTimerLocked()
	s.mu.Unlock()
}

func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	receiveDatagram := s.receiveDatagram
	conn := s.conn
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, errSessionClosed
	}
	var (
		data []byte
		err  error
	)
	if receiveDatagram != nil {
		operationCtx, finish := s.operationContext(ctx)
		data, err = receiveDatagram(operationCtx)
		finish()
	} else if conn != nil {
		data, err = conn.ReceiveDatagram(ctx)
	} else {
		err = errSessionClosed
	}
	if err != nil && callerContextError(ctx, err) == nil {
		if isTerminalSessionError(err) {
			if s.failSession(err) {
				s.emitTerminalWarning(ctx, "quic_datagram_receive_failed", err)
			}
		} else if !s.IsClosed() {
			s.emit(ctx, diagnostic.LevelWarn, "quic_datagram_receive_failed", err, "")
		}
	}
	return data, err
}

func (s *Session) CurrentMaxDatagramSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxDatagramSize
}

func (s *Session) SendDatagram(ctx context.Context, frame []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.mu.Lock()
	sendDatagram := s.sendDatagram
	conn := s.conn
	closed := s.closed
	s.mu.Unlock()
	var err error
	if closed {
		err = errSessionClosed
	} else if sendDatagram != nil {
		operationCtx, finish := s.operationContext(ctx)
		err = sendDatagram(operationCtx, frame)
		finish()
	} else if conn != nil {
		err = conn.SendDatagram(frame)
	} else {
		err = errSessionClosed
	}
	if err == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		if tooLarge.MaxDatagramPayloadSize > 0 {
			s.mu.Lock()
			s.maxDatagramSize = int(tooLarge.MaxDatagramPayloadSize)
			s.mu.Unlock()
		}
		return &nquic.DatagramTooLargeError{
			MaxDatagramSize: s.CurrentMaxDatagramSize(),
			Cause:           err,
		}
	}
	s.maybeFailSession(err)
	return err
}

func (s *Session) LocalAddr() net.Addr {
	s.mu.Lock()
	localAddr := s.localAddr
	conn := s.conn
	s.mu.Unlock()
	if localAddr != nil {
		return localAddr()
	}
	if conn != nil {
		return conn.LocalAddr()
	}
	return nil
}

func isTerminalSessionError(err error) bool {
	if err == nil {
		return false
	}
	// Per-stream EOF/reset must not tear down the shared QUIC session.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) || errors.Is(err, io.EOF) {
		return false
	}
	var appErr *quic.ApplicationError
	var transportErr *quic.TransportError
	return errors.Is(err, net.ErrClosed) || errors.Is(err, errSessionClosed) ||
		errors.As(err, &appErr) || errors.As(err, &transportErr)
}

func (s *Session) maybeFailSession(err error) {
	if isTerminalSessionError(err) {
		s.failSession(err)
	}
}

func (s *Session) failSession(err error) bool {
	if err == nil {
		err = errSessionClosed
	}
	return s.close()
}

func (s *Session) emitTerminalWarning(ctx context.Context, code string, err error) {
	s.terminalWarnOnce.Do(func() {
		s.emit(ctx, diagnostic.LevelWarn, code, err, "")
	})
}

func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) Close() {
	s.close()
}

func (s *Session) close() bool {
	closedNow := false
	s.closeOnce.Do(func() {
		closedNow = true
		var cancel context.CancelFunc
		var conn *quic.Conn
		s.mu.Lock()
		s.closed = true
		if s.idleTimer != nil {
			s.idleTimer.Stop()
			s.idleTimer = nil
		}
		cancel = s.cancel
		conn = s.conn
		s.conn = nil
		s.mu.Unlock()

		close(s.lifetimeDone)
		s.finishReady(errSessionClosed)
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "")
		}
	})
	return closedNow
}

func (s *Session) operationContext(ctx context.Context) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	operationCtx, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	go func() {
		select {
		case <-s.lifetimeDone:
			cancel()
		case <-finished:
		}
	}()
	return operationCtx, func() {
		close(finished)
		cancel()
	}
}

func (s *Session) armIdleTimer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armIdleTimerLocked()
}

func (s *Session) armIdleTimerLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	if s.closed || s.activeConns > 0 {
		return
	}
	delay := s.idleCloseDelay
	s.idleTimer = time.AfterFunc(delay, func() {
		s.mu.Lock()
		if s.closed || s.activeConns > 0 {
			s.mu.Unlock()
			return
		}
		s.closed = true
		s.mu.Unlock()
		s.Close()
		s.emit(context.Background(), diagnostic.LevelDebug, "quic_session_idle_closed", nil, delay.String())
	})
}

func (s *Session) emit(ctx context.Context, level diagnostic.Level, code string, err error, outcome string) {
	if s == nil || s.cfg == nil {
		return
	}
	diagnostic.Emit(ctx, s.cfg.Observer, diagnostic.Event{
		Level: level, Code: code, Component: "mihomo-quic", Target: s.cfg.Addr, Outcome: outcome, Err: err,
	})
}

func (s *Session) disarmIdleTimerLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

var (
	errSessionClosed    = errors.New("nowhere: session closed")
	errConnectionClosed = errors.New("nowhere: connection closed")
)

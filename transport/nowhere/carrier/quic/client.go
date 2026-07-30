package quic

import (
	"context"
	"errors"
	"sync"

	"github.com/ohmycggk/nowhere-go/carrier/dialgate"
)

// Client caches one handshaked Session per proxy behind a coalescing dial gate.
type Client struct {
	cfg        *QUICConfig
	gate       *dialgate.Gate
	newSession func(*QUICConfig) *Session

	mu      sync.Mutex
	session *Session
}

func NewClient(cfg *QUICConfig) *Client {
	initial, max := dialgate.DefaultInitial, dialgate.DefaultMax
	if cfg != nil {
		if cfg.DialBackoffInitial > 0 {
			initial = cfg.DialBackoffInitial
		}
		if cfg.DialBackoffMax > 0 {
			max = cfg.DialBackoffMax
		}
	}
	return &Client{
		cfg:        cfg,
		newSession: NewSession,
		gate: dialgate.New(dialgate.Options{
			Initial:        initial,
			Max:            max,
			AlwaysCoalesce: true,
		}),
	}
}

func (c *Client) AcquireSession(ctx context.Context) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out *Session
	err := c.gate.Run(ctx, func(ctx context.Context) error {
		for {
			c.mu.Lock()
			candidate := c.session
			if candidate != nil && candidate.IsClosed() {
				c.session = nil
				candidate = nil
			}
			if candidate != nil {
				s := candidate
				c.mu.Unlock()
				if err := s.EnsureReady(ctx); err != nil {
					if callerErr := callerContextError(ctx, err); callerErr != nil {
						return callerErr
					}
					c.InvalidateSession(s)
					return err
				}
				if s.IsClosed() {
					c.InvalidateSession(s)
					continue
				}
				out = s
				return nil
			}
			newSession := c.newSession
			if newSession == nil {
				newSession = NewSession
			}
			s := newSession(c.cfg)
			c.session = s
			c.mu.Unlock()

			if err := s.EnsureReady(ctx); err != nil {
				if callerErr := callerContextError(ctx, err); callerErr != nil {
					return callerErr
				}
				c.InvalidateSession(s)
				return err
			}
			out = s
			return nil
		}
	})
	if callerErr := callerContextError(ctx, err); callerErr != nil {
		return nil, callerErr
	}
	if callerErr := ctx.Err(); callerErr != nil {
		return nil, callerErr
	}
	if out == nil {
		c.mu.Lock()
		out = c.session
		c.mu.Unlock()
		if out != nil && !out.IsClosed() {
			if readyErr := out.EnsureReady(ctx); readyErr != nil {
				if callerErr := callerContextError(ctx, readyErr); callerErr != nil {
					return nil, callerErr
				}
				c.InvalidateSession(out)
				return nil, readyErr
			}
		}
	}
	if out != nil && !out.IsClosed() {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("nowhere: quic session unavailable")
}

func callerContextError(ctx context.Context, err error) error {
	if ctx == nil || err == nil {
		return nil
	}
	ctxErr := ctx.Err()
	if ctxErr != nil && errors.Is(err, ctxErr) {
		return ctxErr
	}
	return nil
}

func (c *Client) InvalidateSession(stale *Session) {
	if stale == nil {
		return
	}
	c.mu.Lock()
	if c.session == stale {
		c.session = nil
	}
	c.mu.Unlock()
	stale.Close()
}

func (c *Client) Close() error {
	c.mu.Lock()
	s := c.session
	c.session = nil
	c.mu.Unlock()
	if s != nil {
		s.Close()
	}
	return nil
}

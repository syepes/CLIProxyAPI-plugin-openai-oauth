package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrClosed = errors.New("OAuth token manager is closed")

// Status intentionally excludes all credentials and tokens.
type Status struct {
	Ready               bool      `json:"ready"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
	RefreshAt           time.Time `json:"refresh_at,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	SuccessfulGrants    uint64    `json:"successful_grants"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	Refreshing          bool      `json:"refreshing"`
}

// Manager is a concurrency-safe, memory-only token cache with proactive renewal.
// A canceled caller never cancels another caller's shared token exchange.
type Manager struct {
	cfg                                        Config
	client                                     *http.Client
	ctx                                        context.Context
	cancel                                     context.CancelFunc
	mu                                         sync.Mutex
	token                                      string
	expiresAt, refreshAt, retryAt, lastSuccess time.Time
	lastErr                                    error
	failures                                   int
	successes                                  uint64
	flight                                     chan struct{}
	wake                                       chan struct{}
	closed, started                            bool
	wg                                         sync.WaitGroup
	now                                        func() time.Time
}

func NewManager(cfg Config) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Manager{cfg: cfg, client: client, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), now: time.Now}, nil
}

func (m *Manager) Token(ctx context.Context) (string, error) {
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return "", ErrClosed
		}
		now := m.now()
		if m.token != "" && now.Before(m.refreshAt) {
			v := m.token
			m.mu.Unlock()
			return v, nil
		}
		if m.lastErr != nil && now.Before(m.retryAt) {
			if m.token != "" && now.Before(m.expiresAt) {
				v := m.token
				m.mu.Unlock()
				return v, nil
			}
			err := m.lastErr
			m.mu.Unlock()
			return "", err
		}
		if m.flight == nil {
			m.flight = make(chan struct{})
			m.wg.Add(1)
			go m.acquire(m.flight)
		}
		done := m.flight
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-m.ctx.Done():
			return "", ErrClosed
		case <-done:
		}
	}
}

// Invalidate discards only the token which was actually rejected. Concurrent
// 401s for an older token cannot invalidate a newly acquired token.
func (m *Manager) Invalidate(rejected string) {
	m.mu.Lock()
	if rejected != "" && m.token == rejected {
		m.token = ""
		m.refreshAt = time.Time{}
		m.retryAt = time.Time{}
		m.lastErr = nil
	}
	m.mu.Unlock()
	m.signal()
}

func (m *Manager) Refresh(ctx context.Context) error {
	m.mu.Lock()
	m.refreshAt = m.now()
	m.retryAt = time.Time{}
	m.lastErr = nil
	m.mu.Unlock()
	if _, err := m.Token(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{Ready: !m.closed && m.token != "" && m.now().Before(m.expiresAt), ExpiresAt: m.expiresAt, RefreshAt: m.refreshAt, LastSuccess: m.lastSuccess, SuccessfulGrants: m.successes, ConsecutiveFailures: m.failures, Refreshing: m.flight != nil}
	if m.lastErr != nil {
		s.LastError = m.lastErr.Error()
	}
	return s
}

// Start enables proactive renewal. Token also refreshes on demand if not started.
func (m *Manager) Start() {
	m.mu.Lock()
	if m.started || m.closed {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		for {
			timer := time.NewTimer(m.nextDelay())
			select {
			case <-m.ctx.Done():
				timer.Stop()
				return
			case <-m.wake:
				timer.Stop()
				continue
			case <-timer.C:
			}
			if _, err := m.Token(m.ctx); errors.Is(err, ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
		}
	}()
}

func (m *Manager) nextDelay() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	at := m.refreshAt
	if m.lastErr != nil && m.retryAt.After(at) {
		at = m.retryAt
	}
	d := at.Sub(m.now())
	if d < 0 {
		return 0
	}
	return d
}

func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	m.wg.Wait()
	m.client.CloseIdleConnections()
	m.mu.Lock()
	m.token = ""
	m.cfg.ClientSecret = ""
	m.mu.Unlock()
}

func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) acquire(done chan struct{}) {
	defer m.wg.Done()
	start := m.now()
	token, lifetime, err := m.fetch()
	m.mu.Lock()
	now := m.now()
	if err == nil && !start.Add(lifetime).After(now) {
		err = errors.New("OAuth token expired before the exchange completed")
	}
	if err != nil {
		m.failures++
		m.lastErr = err
		shift := min(m.failures-1, 5)
		m.retryAt = now.Add(time.Second * time.Duration(1<<shift))
	} else if !m.closed {
		m.token = token
		m.expiresAt = start.Add(lifetime)
		skew := min(time.Minute, lifetime/5)
		m.refreshAt = m.expiresAt.Add(-skew)
		m.lastSuccess = now
		m.lastErr = nil
		m.failures = 0
		m.retryAt = time.Time{}
		m.successes++
	}
	m.flight = nil
	close(done)
	m.mu.Unlock()
	m.signal()
}

func (m *Manager) fetch() (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {m.cfg.Scope}}
	if m.cfg.AuthMethod == "client_secret_post" {
		form.Set("client_id", m.cfg.ClientID)
		form.Set("client_secret", m.cfg.ClientSecret)
	}
	ctx, cancel := context.WithTimeout(m.ctx, m.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, errors.New("cannot construct OAuth token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if m.cfg.AuthMethod == "client_secret_basic" {
		req.SetBasicAuth(url.QueryEscape(m.cfg.ClientID), url.QueryEscape(m.cfg.ClientSecret))
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", 0, errors.New("OAuth token endpoint transport failure")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return "", 0, errors.New("OAuth token response is unreadable or exceeds 1 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &body)
		safe := ""
		switch body.Error {
		case "invalid_client", "invalid_scope", "invalid_request", "unauthorized_client", "unsupported_grant_type", "temporarily_unavailable", "server_error":
			safe = ", " + body.Error
		}
		return "", 0, fmt.Errorf("OAuth token endpoint rejected the grant (HTTP %d%s)", resp.StatusCode, safe)
	}
	var body struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if json.Unmarshal(raw, &body) != nil || body.AccessToken == "" || strings.ContainsAny(body.AccessToken, "\r\n") {
		return "", 0, errors.New("OAuth token response has no valid access_token")
	}
	if body.TokenType != "" && !strings.EqualFold(body.TokenType, "Bearer") {
		return "", 0, errors.New("OAuth token_type must be Bearer")
	}
	var value any
	if json.Unmarshal(body.ExpiresIn, &value) != nil {
		return "", 0, errors.New("OAuth token response requires a positive expires_in")
	}
	var seconds float64
	switch v := value.(type) {
	case float64:
		seconds = v
	case string:
		seconds, err = strconv.ParseFloat(v, 64)
	default:
		err = errors.New("invalid expiry")
	}
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > 365*24*3600 {
		return "", 0, errors.New("OAuth expires_in must be positive and at most one year")
	}
	lifetime := time.Duration(seconds * float64(time.Second))
	if lifetime < time.Millisecond {
		return "", 0, errors.New("OAuth token lifetime is too short")
	}
	return body.AccessToken, lifetime, nil
}

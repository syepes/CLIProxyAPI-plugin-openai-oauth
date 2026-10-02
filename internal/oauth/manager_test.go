package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(url string) Config {
	return Config{ClientID: "client", ClientSecret: "secret", Scope: "read write", TokenURL: url, APIURL: url, Timeout: time.Second}
}

func TestConcurrentAcquisitionAndInvalidation(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_secret") != "secret" || r.Form.Get("scope") != "read write" {
			t.Error("incorrect credential grant")
		}
		n := count.Add(1)
		fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, n)
	}))
	defer srv.Close()
	m, err := NewManager(testConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			token, err := m.Token(context.Background())
			if err != nil || token != "token-1" {
				t.Errorf("unexpected token or error: %v", err)
			}
		})
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("grants=%d want 1", count.Load())
	}
	for range 40 {
		wg.Go(func() {
			m.Invalidate("token-1")
			token, err := m.Token(context.Background())
			if err != nil || token != "token-2" {
				t.Errorf("unexpected refreshed token or error: %v", err)
			}
		})
	}
	wg.Wait()
	if count.Load() != 2 {
		t.Fatalf("grants=%d want 2", count.Load())
	}
}

func TestTokenFailureRedactedAndBackedOff(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"secret echoed"}`)
	}))
	defer srv.Close()
	m, err := NewManager(testConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for range 10 {
		_, err = m.Token(context.Background())
		if err == nil || err.Error() != "OAuth token endpoint rejected the grant (HTTP 400, invalid_client)" {
			t.Fatalf("unsafe or missing error: %v", err)
		}
	}
	if count.Load() != 1 {
		t.Fatalf("retry storm: %d grants", count.Load())
	}
}

func TestExpiryAndSoftFailureWithControlledClock(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, `{"access_token":"one","expires_in":100}`)
	}))
	defer srv.Close()
	m, err := NewManager(testConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	now := time.Now()
	m.now = func() time.Time { return now }
	if _, err = m.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	now = now.Add(85 * time.Second)
	if token, err := m.Token(context.Background()); err != nil || token != "one" {
		t.Fatal("unexpired token should remain usable after soft renewal failure")
	}
	now = now.Add(20 * time.Second)
	if _, err = m.Token(context.Background()); err == nil {
		t.Fatal("expired token must never be used")
	}
}

func TestRejectRedirectAndInvalidLifetimes(t *testing.T) {
	for _, body := range []string{`{}`, `{"access_token":"x","expires_in":0}`, `{"access_token":"x","expires_in":-1}`, `{"access_token":"x","expires_in":1e99}`, `{"access_token":"x","expires_in":3600,"token_type":"MAC"}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer srv.Close()
			m, err := NewManager(testConfig(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if _, err = m.Token(context.Background()); err == nil {
				t.Fatal("invalid token response accepted")
			}
		})
	}
	var leaked atomic.Bool
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer dest.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 307) }))
	defer src.Close()
	m, err := NewManager(testConfig(src.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = m.Token(context.Background()); err == nil || leaked.Load() {
		t.Fatal("redirect followed or accepted")
	}
}

func TestCanceledWaiterDoesNotPoisonSharedExchange(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		fmt.Fprint(w, `{"access_token":"shared","expires_in":"3600"}`)
	}))
	defer srv.Close()
	m, err := NewManager(testConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := m.Token(ctx); first <- err }()
	<-started
	cancel()
	if err := <-first; err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
	close(release)
	if token, err := m.Token(context.Background()); err != nil || token != "shared" {
		t.Fatal("shared exchange was canceled")
	}
}

func TestManualRenewalFailurePreservesValidToken(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, `{"access_token":"still-valid","expires_in":3600}`)
	}))
	defer srv.Close()
	m, err := NewManager(testConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("manual renewal hid error")
	}
	if token, err := m.Token(context.Background()); err != nil || token != "still-valid" {
		t.Fatal("manual renewal discarded valid token")
	}
}

func TestBasicAuthenticationAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "client%3Aid" || password != "secret%2Bspace+value" {
			t.Error("basic credentials not form encoded before base64")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("client_secret") != "" {
			t.Error("basic secret also sent in form")
		}
		fmt.Fprint(w, `{"access_token":"basic","expires_in":3600}`)
	}))
	defer srv.Close()
	cfg := testConfig(srv.URL)
	cfg.ClientID = "client:id"
	cfg.ClientSecret = "secret+space value"
	cfg.AuthMethod = "client_secret_basic"
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Close()
	m.Close()
	if _, err := m.Token(context.Background()); err != ErrClosed {
		t.Fatal("closed manager returned token")
	}
}

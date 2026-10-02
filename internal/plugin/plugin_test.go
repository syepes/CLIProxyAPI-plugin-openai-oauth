package plugin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type noHost struct{}

func (noHost) Call(string, any, any) error { return fmt.Errorf("no host") }
func lifecycle(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(LifecycleRequest{ConfigYAML: data, SchemaVersion: 6})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRegistrationAndSecretFreeStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"private-token","expires_in":3600}`)
	}))
	defer srv.Close()
	p := New(noHost{})
	defer p.Close()
	cfg := map[string]any{"CLIENT_ID": "private-client", "CLIENT_SECRET": "private-secret", "CLIENT_SCOPE": "read", "TOKEN_URL": srv.URL, "API_URL": srv.URL, "models": []any{map[string]string{"name": "upstream", "alias": "oauth/test"}}}
	raw := p.Dispatch("plugin.register", lifecycle(t, cfg))
	if strings.Contains(string(raw), "private-") {
		t.Fatal("registration exposed credentials")
	}
	var envelope struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(raw, &envelope) != nil || !envelope.OK {
		t.Fatalf("registration failed: %s", raw)
	}
	got, err := p.Handle("model.static", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.(ModelResponse).Models[0].ID != "oauth/test" {
		t.Fatal("wrong model")
	}
	result := p.Dispatch("management.handle", []byte(`{"Method":"GET","Path":"/v0/management/plugins/openai-oauth/status"}`))
	var env struct {
		Result ManagementResponse `json:"result"`
	}
	if json.Unmarshal(result, &env) != nil {
		t.Fatal("bad envelope")
	}
	for _, s := range []string{"private-client", "private-secret", "private-token"} {
		if strings.Contains(string(env.Result.Body), s) {
			t.Fatal("status exposed credentials")
		}
	}
	// A rejected reconfiguration must not silently continue using old credentials.
	p.Dispatch("plugin.reconfigure", lifecycle(t, map[string]any{"CLIENT_SECRET": "missing-inputs"}))
	if _, err := p.runtime(); err == nil {
		t.Fatal("old runtime survived invalid reconfiguration")
	}
}

func TestPreparePreservesResponsesSemantics(t *testing.T) {
	r := &Runtime{aliases: map[string]string{"oauth/test": "actual"}}
	r.credentials.APIURL = "https://example.invalid/v1"
	req := ExecutorRequest{Model: "oauth/test", SourceFormat: "openai-response", Stream: true, Payload: []byte(`{"model":"oauth/test","previous_response_id":"resp_123","input":[{"type":"function_call_output","call_id":"c1","output":"OK"}],"tools":[{"type":"function","name":"echo","parameters":{}}],"store":true}`)}
	url, raw, err := r.prepare(req)
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://example.invalid/v1/responses" {
		t.Fatal(url)
	}
	var body map[string]any
	json.Unmarshal(raw, &body)
	if body["model"] != "actual" || body["previous_response_id"] != "resp_123" || body["store"] != true || body["stream"] != true {
		t.Fatalf("payload changed unexpectedly: %s", raw)
	}
	req.Model = "other"
	if _, _, err := r.prepare(req); err == nil {
		t.Fatal("unknown model accepted")
	}
}

func TestSSEFramingAndTermination(t *testing.T) {
	wire := []byte("event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"é\"}\r\n\r\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n")
	p := newSSEParser("openai-response")
	var out []byte
	for _, b := range wire {
		events, err := p.Feed([]byte{b}, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			out = append(out, e...)
		}
	}
	if _, err := p.Feed(nil, true); err != nil {
		t.Fatal(err)
	}
	if !p.terminal || string(out) != string(wire) {
		t.Fatal("SSE framing or terminal recognition failed")
	}
	for _, s := range []string{"data: {\"type\":\"response.failed\"}\n\n", "event: error\ndata: {\"message\":\"private\"}\n\n", "data: {\"error\":{\"message\":\"secret\"}}\n\n"} {
		if _, err := newSSEParser("responses").Feed([]byte(s), false); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe upstream error handling")
		}
	}
	if _, err := newSSEParser("responses").Feed([]byte("data: truncated"), true); err == nil {
		t.Fatal("truncation accepted")
	}
}

func TestDashboardNoExternalOrPersistentCredentials(t *testing.T) {
	response := dashboard()
	if !strings.Contains(response.Headers.Get("Content-Security-Policy"), "script-src 'sha256-") {
		t.Fatal("missing script CSP")
	}
	for _, forbidden := range []string{"localStorage", "sessionStorage", "https://"} {
		if strings.Contains(string(response.Body), forbidden) {
			t.Fatalf("dashboard contains %s", forbidden)
		}
	}
}

func FuzzSSEFraming(f *testing.F) {
	f.Add([]byte("data: {\"type\":\"response.completed\"}\n\n"), uint8(3))
	f.Add([]byte("data: [DONE]\r\n\r\n"), uint8(5))
	f.Fuzz(func(t *testing.T, data []byte, size uint8) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		width := int(size) + 1
		p := newSSEParser("responses")
		for i := 0; i < len(data); i += width {
			if _, err := p.Feed(data[i:min(i+width, len(data))], false); err != nil {
				return
			}
		}
		_, _ = p.Feed(nil, true)
	})
}

func TestManagementAndRPCContracts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"rpc-token","expires_in":3600}`)
	}))
	defer srv.Close()
	p := New(noHost{})
	defer p.Close()
	fields := map[string]any{"CLIENT_ID": "id", "CLIENT_SECRET": "secret", "CLIENT_SCOPE": "scope", "TOKEN_URL": srv.URL, "API_URL": srv.URL, "models": []any{map[string]string{"name": "upstream", "alias": "oauth/test"}}}
	if _, err := p.Handle("plugin.register", lifecycle(t, fields)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, body string }{
		{"model.route", `{"RequestedModel":"oauth/test"}`}, {"model.route", `{"RequestedModel":"unrelated"}`}, {"model.for_auth", `{}`}, {"executor.identifier", `{}`},
		{"management.register", `{"BasePath":"/v0/management","ResourceBasePath":"/v0/resource/plugins/openai-oauth"}`},
		{"management.handle", `{"Method":"POST","Path":"/v0/management/plugins/openai-oauth/refresh"}`},
		{"management.handle", `{"Method":"GET","Path":"/v0/management/plugins/openai-oauth/status"}`},
		{"management.handle", `{"Method":"GET","Path":"/v0/management/plugins/openai-oauth/notfound"}`},
		{"management.handle", `{"Method":"GET","Path":"/v0/resource/plugins/openai-oauth/dashboard"}`},
		{"management.handle", `{"Method":"POST","Path":"/v0/resource/plugins/openai-oauth/dashboard"}`},
	} {
		if _, err := p.Handle(tc.method, []byte(tc.body)); err != nil {
			t.Fatalf("%s failed: %v", tc.method, err)
		}
	}
	for _, method := range []string{"executor.count_tokens", "executor.http_request", "invalid.method"} {
		if _, err := p.Handle(method, []byte(`{}`)); err == nil {
			t.Fatalf("%s should fail explicitly", method)
		}
	}
	for _, method := range []string{"plugin.register", "model.route", "executor.execute", "management.register", "management.handle"} {
		if _, err := p.Handle(method, []byte(`broken`)); err == nil {
			t.Fatalf("invalid JSON accepted for %s", method)
		}
	}
	if _, err := p.Handle("plugin.register", []byte(`{"schema_version":1}`)); err == nil {
		t.Fatal("old schema accepted")
	}
	if _, err := p.Handle("plugin.quiesce", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Handle("executor.execute", []byte(`{}`)); err == nil {
		t.Fatal("execution after quiesce accepted")
	}
	if _, err := p.Handle("management.handle", []byte(`{"Method":"GET","Path":"/v0/management/plugins/openai-oauth/status"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestModelDiscovery(t *testing.T) {
	for _, test := range []struct {
		name, body    string
		status, count int
	}{
		{"models", `{"data":[{"id":"z"},{"id":"a"}]}`, 200, 2},
		{"unavailable", `{}`, 503, 0}, {"invalid json", `broken`, 200, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					fmt.Fprint(w, `{"access_token":"discovery-token","expires_in":3600}`)
					return
				}
				if r.Header.Get("Authorization") != "Bearer discovery-token" {
					t.Error("discovery token missing")
				}
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer srv.Close()
			cfg, credentials, err := parseConfig([]byte(fmt.Sprintf("CLIENT_ID: id\nCLIENT_SECRET: secret\nCLIENT_SCOPE: scope\nTOKEN_URL: %s/token\nAPI_URL: %s/v1\n", srv.URL, srv.URL)))
			if err != nil {
				t.Fatal(err)
			}
			r, err := newRuntime(cfg, credentials, noHost{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			models, err := r.Models()
			if err != nil {
				t.Fatal(err)
			}
			if len(models.Models) != test.count {
				t.Fatalf("models=%d want %d", len(models.Models), test.count)
			}
			if test.count > 0 && models.Models[0].ID != "oauth/a" {
				t.Fatal("discovered models not sorted and prefixed")
			}
		})
	}
}

func TestConfigurationValidation(t *testing.T) {
	valid := "CLIENT_ID: id\nCLIENT_SECRET: secret\nCLIENT_SCOPE: scope\nTOKEN_URL: https://id.example/token\nAPI_URL: https://api.example/v1\n"
	for _, suffix := range []string{"unknown_field: value\n", "models:\n  - name: ''\n", "models:\n  - name: a\n    alias: same\n  - name: b\n    alias: same\n", "token_timeout_seconds: 61\n", "token_auth_method: unsupported\n"} {
		if _, _, err := parseConfig([]byte(valid + suffix)); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	cfg, _, err := parseConfig([]byte(valid + "models:\n  - name: a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Models[0].Alias != "oauth/a" {
		t.Fatal("default model prefix not applied")
	}
}

func TestDisabledConfigurationDoesNotResolveSecretsOrStartRuntime(t *testing.T) {
	p := New(noHost{})
	defer p.Close()
	raw := lifecycle(t, map[string]any{"enabled": false, "CLIENT_SECRET": "file:/this/file/does/not/exist"})
	if _, err := p.Handle("plugin.register", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := p.runtime(); err == nil {
		t.Fatal("disabled plugin started a runtime")
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.configError != "plugin is disabled" {
		t.Fatal("disabled plugin resolved credentials")
	}
}

func TestUnchangedReconfigurePreservesRuntime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"cached","expires_in":3600}`)
	}))
	defer srv.Close()
	p := New(noHost{})
	defer p.Close()
	data := lifecycle(t, map[string]any{"enabled": true, "CLIENT_ID": "id", "CLIENT_SECRET": "secret", "CLIENT_SCOPE": "scope", "TOKEN_URL": srv.URL, "API_URL": srv.URL})
	if _, err := p.Handle("plugin.register", data); err != nil {
		t.Fatal(err)
	}
	before, _ := p.runtime()
	if _, err := p.Handle("plugin.reconfigure", data); err != nil {
		t.Fatal(err)
	}
	after, _ := p.runtime()
	if before != after {
		t.Fatal("unchanged configuration replaced token cache")
	}
}

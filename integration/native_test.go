// Package integration tests the compiled shared library inside a real CLIProxyAPI process.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativePlugin(t *testing.T) {
	binary := os.Getenv("CPA_BINARY")
	library := os.Getenv("CPA_PLUGIN_PATH")
	if binary == "" || library == "" {
		t.Skip("set CPA_BINARY and CPA_PLUGIN_PATH for real-host integration")
	}
	var grants atomic.Int64
	var inferenceCalls atomic.Int64
	var accepted atomic.Value
	accepted.Store("")
	var preserved atomic.Bool
	var toolResultReceived atomic.Bool
	slowStarted := make(chan struct{}, 1)
	slowCanceled := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("client_id") != "test-client" || r.Form.Get("client_secret") != "test-secret" || r.Form.Get("scope") != "test-scope" {
				t.Error("incorrect OAuth credentials")
			}
			token := fmt.Sprintf("test-token-%d", grants.Add(1))
			accepted.Store(token)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3}`, token)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+accepted.Load().(string) {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/models" {
			fmt.Fprint(w, `{"data":[{"id":"native-test"}]}`)
			return
		}
		inferenceCalls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if json.Unmarshal(raw, &body) != nil {
			w.WriteHeader(400)
			return
		}
		if body["model"] != "native-test" {
			t.Errorf("model not mapped: %v", body["model"])
		}
		if body["previous_response_id"] == "resp_previous" {
			preserved.Store(true)
		}
		if strings.Contains(string(raw), "wait-for-cancel") {
			select {
			case slowStarted <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			select {
			case slowCanceled <- struct{}{}:
			default:
			}
			return
		}
		if strings.Contains(string(raw), "force-upstream-429") {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":"private-token-must-not-leak"}`)
			return
		}
		if strings.Contains(string(raw), "truncate-stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_truncated\",\"object\":\"response\",\"status\":\"in_progress\",\"output\":[]}}\n\n")
			return
		}
		if stream, _ := body["stream"].(bool); stream {
			w.Header().Set("Content-Type", "text/event-stream")
			var s string
			if r.URL.Path == "/v1/responses" {
				response := `{"id":"resp_test","object":"response","status":"completed","model":"native-test","output":[{"id":"msg_test","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"OK","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`
				s = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_test\",\"object\":\"response\",\"status\":\"in_progress\",\"output\":[]}}\n\n" +
					"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"item_id\":\"msg_test\",\"delta\":\"OK\"}\n\n" +
					"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" + response + "}\n\n"
			} else {
				s = "data: {\"id\":\"chat_test\",\"object\":\"chat.completion.chunk\",\"model\":\"native-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"
			}
			for i := 0; i < len(s); i += 11 {
				end := min(i+11, len(s))
				if _, err := io.WriteString(w, s[i:end]); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/responses" && body["tools"] != nil {
			fmt.Fprint(w, `{"id":"resp_tool","object":"response","status":"completed","model":"native-test","output":[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"echo","arguments":"{\"text\":\"OK\"}"}]}`)
			return
		}
		if strings.Contains(string(raw), "function_call_output") && strings.Contains(string(raw), "call_1") {
			toolResultReceived.Store(true)
		}
		if r.URL.Path == "/v1/responses" {
			fmt.Fprint(w, `{"id":"resp_test","object":"response","status":"completed","model":"native-test","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK"}]}]}`)
		} else {
			fmt.Fprint(w, `{"id":"chat_test","object":"chat.completion","model":"native-test","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
		}
	}))
	defer upstream.Close()
	temp := t.TempDir()
	plugins := filepath.Join(temp, "plugins", runtime.GOOS, runtime.GOARCH)
	if err := os.MkdirAll(plugins, 0700); err != nil {
		t.Fatal(err)
	}
	suffix := ".so"
	if runtime.GOOS == "darwin" {
		suffix = ".dylib"
	}
	data, err := os.ReadFile(library)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(plugins, "openai-oauth"+suffix), data, 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg := map[string]any{"host": "127.0.0.1", "port": port, "auth-dir": filepath.Join(temp, "auths"), "api-keys": []string{"client-test-key"}, "remote-management": map[string]any{"secret-key": "management-test-key", "disable-control-panel": true, "disable-auto-update-panel": true}, "request-retry": 0, "max-retry-interval": 0, "request-log": false, "error-logs-max-files": 0, "logging-to-file": false, "commercial-mode": true,
		"plugins": map[string]any{"enabled": true, "dir": filepath.Join(temp, "plugins"), "configs": map[string]any{"openai-oauth": map[string]any{"enabled": true, "CLIENT_ID": "test-client", "CLIENT_SECRET": "test-secret", "CLIENT_SCOPE": "test-scope", "TOKEN_URL": upstream.URL + "/token", "API_URL": upstream.URL + "/v1", "model_prefix": "oauth"}}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(temp, "config.json")
	os.WriteFile(configPath, raw, 0600)
	logPath := filepath.Join(temp, "host.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--config", configPath, "--local-model")
	cmd.Dir = temp
	cmd.Stdout = log
	cmd.Stderr = log
	// Do not give the isolated host the user's real gateway credentials.
	for _, env := range os.Environ() {
		name, _, _ := strings.Cut(env, "=")
		switch name {
		case "CLIENT_ID", "CLIENT_SECRET", "CLIENT_SCOPE", "SCOPE", "TOKEN_URL", "API_URL":
			continue
		}
		cmd.Env = append(cmd.Env, env)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		log.Close()
		if t.Failed() {
			output, _ := os.ReadFile(logPath)
			lines := strings.Split(string(output), "\n")
			if len(lines) > 65 {
				lines = append(lines[:35], lines[len(lines)-30:]...)
			}
			t.Logf("CLIProxyAPI log:\n%s", strings.Join(lines, "\n"))
		}
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 8 * time.Second}
	request := func(method, path, key string, body any) (int, []byte) {
		t.Helper()
		var payload []byte
		if body != nil {
			payload, _ = json.Marshal(body)
		}
		req, err := http.NewRequest(method, base+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, raw
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		req, _ := http.NewRequest("GET", base+"/v1/models", nil)
		req.Header.Set("Authorization", "Bearer client-test-key")
		resp, err := client.Do(req)
		ready := false
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ready = strings.Contains(string(body), "oauth/native-test")
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("plugin model was not registered")
		}
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("host exited before readiness: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Run("native protocols", func(t *testing.T) {
		for _, route := range []string{"/v1/chat/completions", "/v1/responses"} {
			for _, stream := range []bool{false, true} {
				payload := map[string]any{"model": "oauth/native-test", "stream": stream}
				if strings.HasSuffix(route, "responses") {
					payload["input"] = "Reply OK"
					payload["previous_response_id"] = "resp_previous"
				} else {
					payload["messages"] = []any{map[string]string{"role": "user", "content": "Reply OK"}}
				}
				status, raw := request("POST", route, "client-test-key", payload)
				if status != 200 || !bytes.Contains(raw, []byte("OK")) {
					t.Fatalf("%s stream=%v: status=%d body=%s", route, stream, status, raw)
				}
			}
		}
		if !preserved.Load() {
			t.Fatal("native Responses previous_response_id was removed")
		}
	})
	t.Run("upstream errors and truncated streams", func(t *testing.T) {
		status, body := request("POST", "/v1/responses", "client-test-key", map[string]any{"model": "oauth/native-test", "input": "force-upstream-429"})
		if status != 429 || bytes.Contains(body, []byte("private-token")) {
			t.Fatalf("unsafe or incorrect upstream error: %d %s", status, body)
		}
		status, body = request("POST", "/v1/responses", "client-test-key", map[string]any{"model": "oauth/native-test", "input": "truncate-stream", "stream": true})
		if status != 200 || !bytes.Contains(body, []byte("error")) || bytes.Contains(body, []byte("response.completed")) {
			t.Fatalf("truncated stream reported success: %d %s", status, body)
		}
	})
	t.Run("function tool round trip", func(t *testing.T) {
		status, body := request("POST", "/v1/responses", "client-test-key", map[string]any{"model": "oauth/native-test", "input": "Call echo with OK", "tools": []any{map[string]any{"type": "function", "name": "echo", "parameters": map[string]any{"type": "object", "properties": map[string]any{"text": map[string]string{"type": "string"}}}}}})
		if status != 200 || !bytes.Contains(body, []byte(`"call_id":"call_1"`)) {
			t.Fatalf("tool call failed: %d %s", status, body)
		}
		status, body = request("POST", "/v1/responses", "client-test-key", map[string]any{"model": "oauth/native-test", "input": []any{map[string]string{"type": "function_call_output", "call_id": "call_1", "output": "OK"}}})
		if status != 200 || !toolResultReceived.Load() || !bytes.Contains(body, []byte("OK")) {
			t.Fatalf("tool result failed: %d %s", status, body)
		}
	})
	t.Run("management protection", func(t *testing.T) {
		status, _ := request("GET", "/v0/management/plugins/openai-oauth/status", "", nil)
		if status != 401 && status != 403 {
			t.Fatalf("unprotected management status %d", status)
		}
		status, body := request("GET", "/v0/management/plugins/openai-oauth/status", "management-test-key", nil)
		if status != 200 {
			t.Fatalf("status=%d body=%s", status, body)
		}
		for _, secret := range []string{"test-secret", "test-token-"} {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("status leaks secrets")
			}
		}
		status, body = request("GET", "/v0/resource/plugins/openai-oauth/dashboard", "", nil)
		if status != 200 || !bytes.Contains(body, []byte("OpenAI OAuth")) {
			t.Fatalf("dashboard unavailable %d", status)
		}
	})
	t.Run("automatic renewal while idle", func(t *testing.T) {
		initial := grants.Load()
		timer := time.NewTimer(8 * time.Second)
		defer timer.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for grants.Load() <= initial {
			select {
			case <-timer.C:
				t.Fatal("token was not renewed automatically")
			case <-ticker.C:
			}
		}
	})
	t.Run("revoked token 401 recovery", func(t *testing.T) {
		accepted.Store("revoked")
		status, body := request("POST", "/v1/chat/completions", "client-test-key", map[string]any{"model": "oauth/native-test", "messages": []any{map[string]string{"role": "user", "content": "OK"}}})
		if status != 200 {
			t.Fatalf("401 recovery failed: %d %s", status, body)
		}
	})
	t.Run("upstream cancellation before headers", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", base+"/v1/responses", strings.NewReader(`{"model":"oauth/native-test","input":"wait-for-cancel","stream":true}`))
		req.Header.Set("Authorization", "Bearer client-test-key")
		req.Header.Set("Content-Type", "application/json")
		done := make(chan struct{})
		go func() {
			defer close(done)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
		select {
		case <-slowStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("upstream never started")
		}
		cancel()
		select {
		case <-slowCanceled:
		case <-time.After(5 * time.Second):
			t.Fatal("upstream did not observe cancellation")
		}
		<-done
	})
	t.Run("Edit config exposes model exclusions", func(t *testing.T) {
		code, body := request("GET", "/v0/management/plugins", "management-test-key", nil)
		var listing struct {
			Plugins []struct {
				ID     string `json:"id"`
				Fields []struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"config_fields"`
			} `json:"plugins"`
		}
		if code != 200 || json.Unmarshal(body, &listing) != nil {
			t.Fatalf("plugin metadata: %d %s", code, body)
		}
		for _, plugin := range listing.Plugins {
			if plugin.ID != "openai-oauth" {
				continue
			}
			for _, field := range plugin.Fields {
				if field.Name == "models_excluded" && field.Type == "array" {
					return
				}
			}
		}
		t.Fatal("Edit config metadata lacks models_excluded array")
	})
	t.Run("model exclusions through Edit config", func(t *testing.T) {
		patch := func(config map[string]any, expected ...string) {
			t.Helper()
			code, body := request("PATCH", "/v0/management/plugins/openai-oauth/config", "management-test-key", config)
			if code != 200 {
				t.Fatalf("config update: %d %s", code, body)
			}
			code, body = request("GET", "/v0/management/plugins/openai-oauth/status", "management-test-key", nil)
			if code != 200 {
				t.Fatalf("plugin unhealthy after config update: %d %s", code, body)
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				code, body = request("GET", "/v1/models", "client-test-key", nil)
				var listing struct {
					Data []struct {
						ID string `json:"id"`
					} `json:"data"`
				}
				matches := code == 200 && json.Unmarshal(body, &listing) == nil && len(listing.Data) == len(expected)
				for _, want := range expected {
					found := false
					for _, model := range listing.Data {
						if model.ID == want {
							found = true
						}
					}
					matches = matches && found
				}
				if matches {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("models after config update: %d %s; want %v", code, body, expected)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		// A nonmatching prefix must not disable the plugin or remove its models.
		patch(map[string]any{"models_excluded": []string{"other-"}}, "oauth/native-test")
		patch(map[string]any{"models_excluded": []string{" NATIVE- ", "native-", ""}})
		before := inferenceCalls.Load()
		for _, model := range []string{"oauth/native-test", "friendly"} {
			if model == "friendly" {
				patch(map[string]any{"models": []any{map[string]string{"name": "native-test", "alias": model}}})
			}
			for _, route := range []string{"/v1/chat/completions", "/v1/responses"} {
				for _, stream := range []bool{false, true} {
					code, body := request("POST", route, "client-test-key", map[string]any{"model": model, "input": "OK", "messages": []any{map[string]string{"role": "user", "content": "OK"}}, "stream": stream})
					if code < 400 || inferenceCalls.Load() != before {
						t.Fatalf("excluded model accepted: %s %s: %d %s", model, route, code, body)
					}
				}
			}
		}
		patch(map[string]any{"models_excluded": []string{}}, "friendly")
		code, body := request("POST", "/v1/responses", "client-test-key", map[string]any{"model": "friendly", "input": "OK"})
		if code != 200 || inferenceCalls.Load() != before+1 {
			t.Fatalf("clearing exclusions did not restore inference: %d %s", code, body)
		}
		patch(map[string]any{"models": []any{}}, "oauth/native-test")
	})
	if path := os.Getenv("CPA_UI_STATE"); path != "" {
		raw, _ := json.Marshal(map[string]string{"base_url": base, "management_key": "management-test-key"})
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.NewTimer(2 * time.Minute)
		defer deadline.Stop()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := os.Stat(path + ".done"); err == nil {
				break
			}
			select {
			case <-deadline.C:
				t.Fatal("browser QA fixture timed out")
			case <-ticker.C:
			}
		}
	}
}

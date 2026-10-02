package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"cliproxyapi-oauth/internal/oauth"
)

// localHost implements the public host-callback wire contract over real HTTP.
type localHost struct {
	mu         sync.Mutex
	sequence   int
	operations map[string]context.CancelFunc
	contexts   map[string]context.Context
	streams    map[string]io.ReadCloser
	emitted    [][]byte
	done       chan string
}

func newLocalHost() *localHost {
	return &localHost{operations: map[string]context.CancelFunc{}, contexts: map[string]context.Context{}, streams: map[string]io.ReadCloser{}, done: make(chan string, 1)}
}
func assign(dst, src any) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}
func (h *localHost) Call(method string, request, response any) error {
	switch method {
	case "host.http.operation_open":
		h.mu.Lock()
		h.sequence++
		id := strconv.Itoa(h.sequence)
		ctx, cancel := context.WithCancel(context.Background())
		h.operations[id] = cancel
		h.contexts[id] = ctx
		h.mu.Unlock()
		return assign(response, hostOperation{OperationID: id})
	case "host.http.cancel":
		req := request.(hostOperation)
		h.mu.Lock()
		cancel := h.operations[req.OperationID]
		h.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return nil
	case "host.http.do_stream":
		req := request.(hostRequest)
		h.mu.Lock()
		ctx := h.contexts[req.OperationID]
		h.mu.Unlock()
		r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
		if err != nil {
			return err
		}
		r.Header = req.Headers
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			return err
		}
		h.mu.Lock()
		h.streams[req.OperationID] = resp.Body
		h.mu.Unlock()
		return assign(response, hostStream{StatusCode: resp.StatusCode, Headers: resp.Header, StreamID: req.OperationID})
	case "host.http.stream_read":
		id := request.(streamID).StreamID
		h.mu.Lock()
		body := h.streams[id]
		h.mu.Unlock()
		if body == nil {
			return errors.New("closed")
		}
		buffer := make([]byte, 64)
		n, err := body.Read(buffer)
		chunk := hostChunk{Payload: buffer[:n], Done: err == io.EOF}
		if err != nil && err != io.EOF {
			chunk.Error = "read canceled"
		}
		return assign(response, chunk)
	case "host.http.stream_close":
		id := request.(streamID).StreamID
		h.mu.Lock()
		body := h.streams[id]
		cancel := h.operations[id]
		delete(h.streams, id)
		h.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if body != nil {
			return body.Close()
		}
		return nil
	case "host.stream.emit":
		req := request.(emitChunk)
		h.mu.Lock()
		h.emitted = append(h.emitted, bytes.Clone(req.Payload))
		h.mu.Unlock()
		return nil
	case "host.stream.close":
		h.done <- request.(emitChunk).Error
		return nil
	default:
		return fmt.Errorf("unknown callback %s", method)
	}
}

func runtimeForServer(t *testing.T, handler http.HandlerFunc) (*Runtime, *localHost) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			fmt.Fprint(w, `{"access_token":"private-token","expires_in":3600}`)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	host := newLocalHost()
	r, err := newRuntime(Config{Models: []ModelConfig{{Name: "upstream", Alias: "oauth/test"}}}, oauth.Config{ClientID: "id", ClientSecret: "secret", Scope: "scope", TokenURL: server.URL + "/token", APIURL: server.URL + "/v1"}, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r, host
}
func execRequest() ExecutorRequest {
	return ExecutorRequest{Model: "oauth/test", SourceFormat: "openai-response", HostCallbackID: "callback-1", StreamID: "downstream-1", Payload: []byte(`{"model":"oauth/test","input":"hello","previous_response_id":"previous","tools":[{"type":"function","name":"echo"}]}`)}
}

func TestExecutorPreservesPayloadAndStripsClientCredentials(t *testing.T) {
	r, _ := runtimeForServer(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer private-token" || req.Header.Get("Cookie") != "" || req.Header.Get("X-Api-Key") != "" {
			t.Error("downstream credential leaked or token not injected")
		}
		var payload map[string]any
		json.NewDecoder(req.Body).Decode(&payload)
		if payload["previous_response_id"] != "previous" || payload["tools"] == nil || payload["model"] != "upstream" {
			t.Error("native Responses fields lost")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "private")
		fmt.Fprint(w, `{"object":"response","status":"completed","output":[]}`)
	})
	req := execRequest()
	req.Headers = http.Header{"Authorization": {"Bearer downstream-secret"}, "Cookie": {"session=private"}, "X-Api-Key": {"private"}}
	response, err := r.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Headers.Get("Set-Cookie") != "" {
		t.Fatal("upstream cookie leaked")
	}
}

func TestExecutorDoesNotExposeUpstreamErrorBodies(t *testing.T) {
	r, _ := runtimeForServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(429)
		fmt.Fprint(w, `{"error":"private-token private-secret"}`)
	})
	_, err := r.Execute(execRequest())
	var rpc *RPCError
	if !errors.As(err, &rpc) || rpc.HTTPStatus != 429 || rpc.Message != "upstream API rejected request (HTTP 429)" {
		t.Fatalf("wrong safe error: %v", err)
	}
}

func TestRuntimeCloseCancelsBeforeHeaders(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	r, _ := runtimeForServer(t, func(w http.ResponseWriter, req *http.Request) {
		close(started)
		<-req.Context().Done()
		close(canceled)
	})
	done := make(chan error, 1)
	go func() { _, err := r.Execute(execRequest()); done <- err }()
	<-started
	r.Close()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel upstream operation")
	}
	if err := <-done; err == nil {
		t.Fatal("canceled request succeeded")
	}
}

func TestStreamTruncationIsNotSuccess(t *testing.T) {
	r, h := runtimeForServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.created\"}\n\n")
	})
	if _, err := r.ExecuteStream(execRequest()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-h.done:
		if err != "upstream stream ended without a terminal event" {
			t.Fatalf("wrong terminal failure %q", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream never closed")
	}
}

func TestRuntimeCloseCancelsActiveStream(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	r, h := runtimeForServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.created\"}\n\n")
		w.(http.Flusher).Flush()
		close(started)
		<-req.Context().Done()
		close(canceled)
	})
	if _, err := r.ExecuteStream(execRequest()); err != nil {
		t.Fatal(err)
	}
	<-started
	r.Close()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel stream")
	}
	select {
	case <-h.done:
	default:
		t.Fatal("downstream stream not closed")
	}
}

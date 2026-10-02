package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cliproxyapi-oauth/internal/oauth"
)

type Runtime struct {
	cfg         Config
	credentials oauth.Config
	tokens      *oauth.Manager
	host        Host
	ctx         context.Context
	cancel      context.CancelFunc
	client      *http.Client
	mu          sync.Mutex
	aliases     map[string]string
	streams     map[string]string
	operations  map[string]bool
	modelErr    string
	closed      bool
	wg          sync.WaitGroup
}

func newRuntime(cfg Config, credentials oauth.Config, host Host) (*Runtime, error) {
	manager, err := oauth.NewManager(credentials)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt := &Runtime{cfg: cfg, credentials: credentials, tokens: manager, host: host, ctx: ctx, cancel: cancel,
		client:  &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone(), Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		aliases: map[string]string{}, streams: map[string]string{}, operations: map[string]bool{}}
	for _, m := range cfg.Models {
		if !cfg.modelExcluded(m.Name) {
			rt.aliases[m.Alias] = m.Name
		}
	}
	manager.Start()
	return rt, nil
}

func (r *Runtime) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.cancel()
	streams := make([]string, 0, len(r.streams))
	for s := range r.streams {
		streams = append(streams, s)
	}
	operations := make([]string, 0, len(r.operations))
	for id := range r.operations {
		operations = append(operations, id)
	}
	r.mu.Unlock()
	for _, id := range operations {
		r.cancelOperation(id)
	}
	for _, s := range streams {
		_ = r.host.Call("host.http.stream_close", streamID{s}, &struct{}{})
	}
	r.tokens.Close()
	r.wg.Wait()
	r.client.CloseIdleConnections()
}

func (r *Runtime) Models() (ModelResponse, error) {
	r.mu.Lock()
	configured := len(r.cfg.Models) > 0
	cached := len(r.aliases) > 0
	r.mu.Unlock()
	if !configured && !cached {
		token, err := r.tokens.Token(r.ctx)
		if err != nil {
			r.setModelError("model discovery could not acquire OAuth token")
			return ModelResponse{Provider: ID, Models: []ModelInfo{}}, nil
		}
		for attempt := 0; attempt < 2; attempt++ {
			req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.credentials.APIURL+"/models", nil)
			if err != nil {
				return ModelResponse{}, fail(500, "invalid model discovery request")
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", "application/json")
			resp, err := r.client.Do(req)
			if err != nil {
				r.setModelError("model discovery transport failure")
				break
			}
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
			resp.Body.Close()
			if resp.StatusCode == 401 && attempt == 0 {
				r.tokens.Invalidate(token)
				token, err = r.tokens.Token(r.ctx)
				if err == nil {
					continue
				}
			}
			if resp.StatusCode != 200 || readErr != nil || len(raw) > 4<<20 {
				r.setModelError("model discovery failed; configure models explicitly or retry plugin reload")
				break
			}
			var result struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &result) != nil {
				r.setModelError("model discovery response is not a model list")
				break
			}
			r.mu.Lock()
			for _, m := range result.Data {
				if m.ID != "" && len(m.ID) <= 512 && len(r.aliases) < 2048 && !r.cfg.modelExcluded(m.ID) {
					r.aliases[r.cfg.ModelPrefix+m.ID] = m.ID
				}
			}
			r.modelErr = ""
			r.mu.Unlock()
			break
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	models := make([]ModelInfo, 0, len(r.aliases))
	for alias, name := range r.aliases {
		models = append(models, ModelInfo{ID: alias, Name: name, DisplayName: name, Object: "model", OwnedBy: ID, UserDefined: true})
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
	return ModelResponse{Provider: ID, Models: models}, nil
}
func (r *Runtime) setModelError(value string) { r.mu.Lock(); r.modelErr = value; r.mu.Unlock() }

func (r *Runtime) Status() any {
	r.mu.Lock()
	count := len(r.aliases)
	modelErr := r.modelErr
	closed := r.closed
	streams := len(r.streams)
	r.mu.Unlock()
	return struct {
		Provider      string       `json:"provider"`
		Version       string       `json:"version"`
		Closed        bool         `json:"closed"`
		Models        int          `json:"models"`
		ActiveStreams int          `json:"active_streams"`
		ModelError    string       `json:"model_error,omitempty"`
		Token         oauth.Status `json:"token"`
	}{ID, Version, closed, count, streams, modelErr, r.tokens.Status()}
}

func (r *Runtime) prepare(req ExecutorRequest) (string, []byte, error) {
	route := ""
	switch req.SourceFormat {
	case "openai", "chat-completions":
		route = "/chat/completions"
	case "openai-response", "responses", "codex":
		route = "/responses"
	default:
		return "", nil, fail(400, "unsupported upstream protocol")
	}
	if req.Alt != "" {
		if req.Alt != "responses/compact" || route != "/responses" || req.Stream {
			return "", nil, fail(400, "unsupported alternate API route")
		}
		route = "/responses/compact"
	}
	r.mu.Lock()
	name, ok := r.aliases[req.Model]
	r.mu.Unlock()
	if !ok {
		return "", nil, fail(404, "model is not registered by this OAuth plugin")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(req.Payload, &body) != nil || body == nil {
		return "", nil, fail(400, "inference payload must be a JSON object")
	}
	// Preserve every other field, including Responses conversation state and tools.
	body["model"], _ = json.Marshal(name)
	if req.Alt == "responses/compact" {
		delete(body, "stream")
	} else {
		body["stream"], _ = json.Marshal(req.Stream)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", nil, fail(400, "cannot encode inference request")
	}
	return r.credentials.APIURL + route, payload, nil
}

func (r *Runtime) open(req ExecutorRequest) (hostStream, error) {
	endpoint, body, err := r.prepare(req)
	if err != nil {
		return hostStream{}, err
	}
	if req.HostCallbackID == "" {
		return hostStream{}, fail(500, "missing request cancellation context")
	}
	token, err := r.tokens.Token(r.ctx)
	if err != nil {
		return hostStream{}, fail(503, err.Error())
	}
	for attempt := 0; attempt < 2; attempt++ {
		headers := http.Header{"Authorization": {"Bearer " + token}, "Content-Type": {"application/json"}, "Accept": {"application/json"}}
		if req.Stream {
			headers.Set("Accept", "text/event-stream")
		}
		// Never forward downstream authentication, cookies, or arbitrary routing headers.
		for _, name := range []string{"OpenAI-Beta", "Idempotency-Key"} {
			if v := req.Headers.Get(name); v != "" {
				headers.Set(name, v)
			}
		}
		var operation hostOperation
		if err := r.host.Call("host.http.operation_open", hostOperation{HostCallbackID: req.HostCallbackID}, &operation); err != nil || operation.OperationID == "" {
			return hostStream{}, fail(502, "cannot open cancellable upstream operation")
		}
		r.mu.Lock()
		stopping := r.closed
		if !stopping {
			r.operations[operation.OperationID] = true
		}
		r.mu.Unlock()
		if stopping {
			r.cancelOperation(operation.OperationID)
			return hostStream{}, fail(503, "plugin is stopping")
		}
		var stream hostStream
		err = r.host.Call("host.http.do_stream", hostRequest{OperationID: operation.OperationID, HostCallbackID: req.HostCallbackID, Method: http.MethodPost, URL: endpoint, Headers: headers, Body: body}, &stream)
		if err != nil {
			r.cancelOperation(operation.OperationID)
			return hostStream{}, fail(502, "upstream request failed or was canceled")
		}
		if stream.StreamID == "" {
			r.cancelOperation(operation.OperationID)
			return hostStream{}, fail(502, "host did not open an upstream stream")
		}
		r.mu.Lock()
		closed := r.closed
		if !closed {
			r.streams[stream.StreamID] = operation.OperationID
		}
		r.mu.Unlock()
		if closed {
			r.cancelOperation(operation.OperationID)
			r.closeStream(stream.StreamID)
			return hostStream{}, fail(503, "plugin is stopping")
		}
		if stream.StatusCode == 401 && attempt == 0 {
			r.closeStream(stream.StreamID)
			r.tokens.Invalidate(token)
			token, err = r.tokens.Token(r.ctx)
			if err != nil {
				return hostStream{}, fail(503, err.Error())
			}
			continue
		}
		if stream.StatusCode < 200 || stream.StatusCode >= 300 {
			r.closeStream(stream.StreamID)
			return hostStream{}, statusError(stream.StatusCode)
		}
		if req.Stream && !strings.HasPrefix(strings.ToLower(stream.Headers.Get("Content-Type")), "text/event-stream") {
			r.closeStream(stream.StreamID)
			return hostStream{}, fail(502, "upstream did not return an SSE stream")
		}
		return stream, nil
	}
	return hostStream{}, fail(401, "upstream rejected renewed OAuth token")
}

func (r *Runtime) closeStream(id string) {
	r.mu.Lock()
	operation := r.streams[id]
	delete(r.streams, id)
	delete(r.operations, operation)
	r.mu.Unlock()
	_ = r.host.Call("host.http.stream_close", streamID{id}, &struct{}{})
}

func (r *Runtime) cancelOperation(id string) {
	r.mu.Lock()
	delete(r.operations, id)
	r.mu.Unlock()
	_ = r.host.Call("host.http.cancel", hostOperation{OperationID: id}, &struct{}{})
}

func (r *Runtime) Execute(req ExecutorRequest) (ExecutorResponse, error) {
	req.Stream = false
	stream, err := r.open(req)
	if err != nil {
		return ExecutorResponse{}, err
	}
	defer r.closeStream(stream.StreamID)
	body := make([]byte, 0, 4096)
	for {
		var chunk hostChunk
		if err := r.host.Call("host.http.stream_read", streamID{stream.StreamID}, &chunk); err != nil || chunk.Error != "" {
			return ExecutorResponse{}, fail(502, "upstream response interrupted or canceled")
		}
		if len(body)+len(chunk.Payload) > 32<<20 {
			return ExecutorResponse{}, fail(502, "upstream response exceeds 32 MiB")
		}
		body = append(body, chunk.Payload...)
		if chunk.Done {
			break
		}
	}
	if !json.Valid(body) {
		return ExecutorResponse{}, fail(502, "upstream response is not JSON")
	}
	return ExecutorResponse{Payload: body, Headers: safeHeaders(stream.Headers)}, nil
}

func (r *Runtime) ExecuteStream(req ExecutorRequest) (StreamResponse, error) {
	req.Stream = true
	if req.StreamID == "" {
		return StreamResponse{}, fail(500, "missing downstream stream ID")
	}
	stream, err := r.open(req)
	if err != nil {
		return StreamResponse{}, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		r.closeStream(stream.StreamID)
		return StreamResponse{}, fail(503, "plugin is stopping")
	}
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		defer r.closeStream(stream.StreamID)
		streamErr := ""
		defer func() {
			_ = r.host.Call("host.stream.close", emitChunk{StreamID: req.StreamID, Error: streamErr}, &struct{}{})
		}()
		parser := newSSEParser(req.SourceFormat)
		for {
			var chunk hostChunk
			if err := r.host.Call("host.http.stream_read", streamID{stream.StreamID}, &chunk); err != nil || chunk.Error != "" {
				streamErr = "upstream stream interrupted or canceled"
				return
			}
			events, err := parser.Feed(chunk.Payload, chunk.Done)
			if err != nil {
				streamErr = err.Error()
				return
			}
			for _, event := range events {
				if err := r.host.Call("host.stream.emit", emitChunk{StreamID: req.StreamID, Payload: event}, &struct{}{}); err != nil {
					return
				}
			}
			if chunk.Done {
				if !parser.terminal {
					streamErr = "upstream stream ended without a terminal event"
				}
				return
			}
		}
	}()
	return StreamResponse{Headers: safeHeaders(stream.Headers)}, nil
}

func safeHeaders(in http.Header) http.Header {
	out := http.Header{}
	for _, k := range []string{"Content-Type", "Cache-Control", "Retry-After", "X-Request-Id", "OpenAI-Request-Id"} {
		if v := in.Values(k); len(v) > 0 {
			for _, value := range v {
				out.Add(k, value)
			}
		}
	}
	return out
}

// Keep generic cancellation errors free of serialized provider responses.
func safeError(err error) *RPCError {
	var rpc *RPCError
	if errors.As(err, &rpc) {
		return rpc
	}
	return &RPCError{Code: "openai_oauth_error", Message: "plugin operation failed", HTTPStatus: 500}
}

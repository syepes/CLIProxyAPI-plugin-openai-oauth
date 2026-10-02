package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Plugin struct {
	mu          sync.RWMutex
	current     *Runtime
	host        Host
	configError string
}

func New(host Host) *Plugin { return &Plugin{host: host} }
func (p *Plugin) Close() {
	p.mu.Lock()
	r := p.current
	p.current = nil
	p.mu.Unlock()
	if r != nil {
		r.Close()
	}
}

func (p *Plugin) runtime() (*Runtime, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.current == nil {
		return nil, fail(503, "OAuth plugin is not configured; check the five required inputs")
	}
	return p.current, nil
}

func (p *Plugin) Handle(method string, raw []byte) (result any, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = fail(500, "plugin operation failed safely")
		}
	}()
	switch method {
	case "plugin.register", "plugin.reconfigure":
		var req LifecycleRequest
		if err := decode(raw, &req); err != nil {
			return nil, err
		}
		if req.SchemaVersion < 6 {
			return nil, fail(400, "CLIProxyAPI plugin schema 6 or newer is required")
		}
		cfg, credentials, configErr := parseConfig(req.ConfigYAML)
		p.mu.RLock()
		same := configErr == nil && cfg.Enabled && p.current != nil && reflect.DeepEqual(p.current.cfg, cfg) && p.current.credentials == credentials
		p.mu.RUnlock()
		if same {
			return registration(), nil
		}
		var rt *Runtime
		if configErr == nil && cfg.Enabled {
			rt, configErr = newRuntime(cfg, credentials, p.host)
		}
		if configErr == nil && !cfg.Enabled {
			configErr = errors.New("plugin is disabled")
		}

		p.mu.Lock()
		old := p.current
		p.current = rt
		p.configError = ""
		if configErr != nil {
			p.configError = configErr.Error()
		}
		p.mu.Unlock()
		if old != nil {
			old.Close()
		}
		return registration(), nil
	case "plugin.quiesce", "plugin.shutdown":
		p.Close()
		return struct{}{}, nil
	case "executor.identifier":
		return map[string]string{"identifier": ID}, nil
	case "model.static":
		r, err := p.runtime()
		if err != nil {
			return ModelResponse{Provider: ID, Models: []ModelInfo{}}, nil
		}
		return r.Models()
	case "model.route":
		var req struct{ RequestedModel string }
		if err := decode(raw, &req); err != nil {
			return nil, err
		}
		r, err := p.runtime()
		if err != nil {
			return map[string]bool{"Handled": false}, nil
		}
		r.mu.Lock()
		_, found := r.aliases[req.RequestedModel]
		r.mu.Unlock()
		return map[string]any{"Handled": found, "TargetKind": "self"}, nil
	case "model.for_auth":
		return ModelResponse{Provider: ID, Models: []ModelInfo{}}, nil
	case "executor.execute", "executor.execute_stream":
		var req ExecutorRequest
		if err := decode(raw, &req); err != nil {
			return nil, err
		}
		r, err := p.runtime()
		if err != nil {
			return nil, err
		}
		if method == "executor.execute_stream" {
			return r.ExecuteStream(req)
		}
		return r.Execute(req)
	case "executor.count_tokens":
		return nil, fail(501, "this OpenAI-compatible gateway does not expose a generic token-counting endpoint")
	case "executor.http_request":
		return nil, fail(501, "arbitrary executor HTTP requests are intentionally disabled")
	case "management.register":
		var req ManagementRegistrationRequest
		if err := decode(raw, &req); err != nil {
			return nil, err
		}
		return map[string]any{"routes": []any{map[string]string{"Method": "GET", "Path": strings.TrimRight(req.BasePath, "/") + "/plugins/" + ID + "/status"}, map[string]string{"Method": "POST", "Path": strings.TrimRight(req.BasePath, "/") + "/plugins/" + ID + "/refresh"}}, "resources": []any{map[string]string{"Path": "/dashboard", "Menu": "OpenAI OAuth", "Description": "OAuth token health and management"}}}, nil
	case "management.handle":
		var req ManagementRequest
		if err := decode(raw, &req); err != nil {
			return nil, err
		}
		return p.manage(req), nil
	default:
		return nil, fail(400, "unsupported plugin RPC method")
	}
}

func (p *Plugin) manage(req ManagementRequest) ManagementResponse {
	if strings.Contains(req.Path, "/resource/plugins/") {
		if req.Method != "GET" {
			return jsonResponse(405, map[string]string{"error": "method not allowed"})
		}
		return dashboard()
	}
	r, err := p.runtime()
	if err != nil {
		p.mu.RLock()
		message := p.configError
		p.mu.RUnlock()
		return jsonResponse(503, map[string]any{"configured": false, "error": message})
	}
	switch {
	case req.Method == "GET" && strings.HasSuffix(req.Path, "/status"):
		return jsonResponse(200, r.Status())
	case req.Method == "POST" && strings.HasSuffix(req.Path, "/refresh"):
		ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
		defer cancel()
		if err := r.tokens.Refresh(ctx); err != nil {
			return jsonResponse(503, map[string]string{"error": err.Error()})
		}
		return jsonResponse(200, r.Status())
	default:
		return jsonResponse(404, map[string]string{"error": "route not found"})
	}
}

func registration() registrationResponse {
	return registrationResponse{
		SchemaVersion: 6,
		Metadata: registrationMetadata{
			Name:             "OpenAI OAuth Provider",
			Version:          Version,
			Author:           "syepes",
			GitHubRepository: Repository,
			ConfigFields: []registrationConfigField{
				{Name: "model_prefix", Type: "string", Description: "Namespace for discovered IDs and configured models without aliases; a trailing slash is optional (default oauth)."},
				{Name: "models", Type: "array", Description: "Optional model allowlist: objects with name and optional alias. Empty discovers all eligible account models."},
				{Name: "models_excluded", Type: "array", Description: "Case-insensitive model ID prefixes omitted from OpenAI discovery to prevent collisions with native providers."},
				{Name: "CLIENT_ID", Type: "string", Description: "Literal, env:NAME, or file:/absolute/path. Defaults to environment variable CLIENT_ID."},
				{Name: "CLIENT_SECRET", Type: "string", Description: "Use env:CLIENT_SECRET or a protected file:/absolute/path. Literal secrets are visible in CLIProxyAPI configuration exports."},
				{Name: "CLIENT_SCOPE", Type: "string", Description: "Literal, env:NAME, or file:/absolute/path. Defaults to environment variable CLIENT_SCOPE."},
				{Name: "TOKEN_URL", Type: "string", Description: "Literal, env:NAME, or file:/absolute/path. Defaults to environment variable TOKEN_URL."},
				{Name: "API_URL", Type: "string", Description: "Literal, env:NAME, or file:/absolute/path. Defaults to environment variable API_URL."},
				{Name: "token_auth_method", Type: "enum", EnumValues: []string{"client_secret_post", "client_secret_basic"}, Description: "OAuth client authentication method (default client_secret_post)."},
				{Name: "token_timeout_seconds", Type: "integer", Description: "Credential request timeout, 1-60 seconds (default 10)."},
			},
		},
		Capabilities: registrationCapability{
			ModelProvider:         true,
			ModelRouter:           true,
			Executor:              true,
			ExecutorModelScope:    "static",
			ExecutorInputFormats:  []string{"chat-completions", "responses"},
			ExecutorOutputFormats: []string{"chat-completions", "responses"},
			ManagementAPI:         true,
		},
	}
}

// Dispatch returns the wire envelope expected by the native plugin ABI.
func (p *Plugin) Dispatch(method string, raw []byte) []byte {
	result, err := p.Handle(method, raw)
	envelope := Envelope{OK: err == nil, Result: result}
	if err != nil {
		var rpc *RPCError
		if errors.As(err, &rpc) {
			envelope.Error = rpc
		} else {
			envelope.Error = safeError(err)
		}
	}
	encoded, encodeErr := json.Marshal(envelope)
	if encodeErr != nil {
		return []byte(`{"ok":false,"error":{"code":"internal_error","message":"cannot encode plugin response","http_status":500}}`)
	}
	return encoded
}

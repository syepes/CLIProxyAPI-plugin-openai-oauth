package plugin

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Host is the native C ABI callback interface. Implementations must be thread-safe.
type Host interface {
	Call(method string, request any, response any) error
}

type RPCError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }
func fail(status int, message string) error {
	return &RPCError{Code: "openai_oauth_error", Message: message, HTTPStatus: status}
}

type Envelope struct {
	OK     bool      `json:"ok"`
	Result any       `json:"result,omitempty"`
	Error  *RPCError `json:"error,omitempty"`
}
type LifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

// Registration types mirror the native ABI without importing the host SDK.
type registrationResponse struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      registrationMetadata   `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}
type registrationMetadata struct {
	Name             string
	Version          string
	Author           string
	GitHubRepository string
	ConfigFields     []registrationConfigField
}
type registrationConfigField struct {
	Name        string
	Type        string
	Description string
	EnumValues  []string `json:"EnumValues,omitempty"`
}
type registrationCapability struct {
	ModelProvider         bool     `json:"model_provider"`
	ModelRouter           bool     `json:"model_router"`
	Executor              bool     `json:"executor"`
	ExecutorModelScope    string   `json:"executor_model_scope"`
	ExecutorInputFormats  []string `json:"executor_input_formats"`
	ExecutorOutputFormats []string `json:"executor_output_formats"`
	ManagementAPI         bool     `json:"management_api"`
}
type ExecutorRequest struct {
	Model           string
	SourceFormat    string
	Format          string
	Stream          bool
	Alt             string
	Headers         http.Header
	Payload         []byte
	OriginalRequest []byte
	HostCallbackID  string `json:"host_callback_id"`
	StreamID        string `json:"stream_id"`
}
type ExecutorResponse struct {
	Payload []byte
	Headers http.Header
}
type StreamResponse struct {
	Headers http.Header `json:"headers"`
}
type ModelInfo struct {
	ID, Object, OwnedBy, Name, DisplayName string
	UserDefined                            bool
}
type ModelResponse struct {
	Provider string
	Models   []ModelInfo
}
type ManagementRegistrationRequest struct{ BasePath, ResourceBasePath string }
type ManagementRequest struct {
	Method, Path string
	Headers      http.Header
	Body         []byte
}
type ManagementResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}
type hostOperation struct {
	HostCallbackID string `json:"host_callback_id,omitempty"`
	OperationID    string `json:"operation_id,omitempty"`
}

type hostRequest struct {
	OperationID    string      `json:"operation_id,omitempty"`
	HostCallbackID string      `json:"host_callback_id,omitempty"`
	Method         string      `json:"method"`
	URL            string      `json:"url"`
	Headers        http.Header `json:"headers"`
	Body           []byte      `json:"body,omitempty"`
}
type hostStream struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	StreamID   string      `json:"stream_id"`
}
type streamID struct {
	StreamID string `json:"stream_id"`
}
type hostChunk struct {
	Payload []byte `json:"payload"`
	Error   string `json:"error"`
	Done    bool   `json:"done"`
}
type emitChunk struct {
	StreamID string `json:"stream_id"`
	Payload  []byte `json:"payload,omitempty"`
	Error    string `json:"error,omitempty"`
}

func decode(raw []byte, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fail(400, "invalid plugin request JSON")
	}
	return nil
}
func jsonResponse(status int, v any) ManagementResponse {
	body, err := json.Marshal(v)
	if err != nil {
		body = []byte(`{"error":"cannot encode response"}`)
		status = 500
	}
	return ManagementResponse{status, http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, body}
}
func statusError(status int) error {
	if status < 400 || status > 599 {
		return fail(502, "upstream returned an unexpected HTTP status")
	}
	return fail(status, fmt.Sprintf("upstream API rejected request (HTTP %d)", status))
}

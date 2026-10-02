package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestModelsExcludedConfig(t *testing.T) {
	const valid = "CLIENT_ID: id\nCLIENT_SECRET: secret\nCLIENT_SCOPE: scope\nTOKEN_URL: https://example.invalid/token\nAPI_URL: https://example.invalid/v1\n"
	cfg, _, err := parseConfig([]byte(valid + "models_excluded: [' Claude- ', claude-, '', '  ', GPT-]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.ModelsExcluded, []string{"claude-", "gpt-"}) {
		t.Fatalf("normalized exclusions: %v", cfg.ModelsExcluded)
	}
	for _, invalid := range []string{"invalid", "{name: model}", "[{name: model}]"} {
		if _, _, err := parseConfig([]byte(valid + "models_excluded: " + invalid)); err == nil {
			t.Fatalf("accepted invalid exclusions: %s", invalid)
		}
	}
	for _, extra := range []string{"", "models_excluded: []", "models_excluded: ['', '  ']"} {
		cfg, _, err := parseConfig([]byte(valid + extra))
		if err != nil || len(cfg.ModelsExcluded) != 0 {
			t.Fatalf("empty exclusions: %v %v", cfg.ModelsExcluded, err)
		}
	}
}

func TestModelsExcludedLifecycle(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(fmt.Sprintf("configured=%v", configured), func(t *testing.T) {
			var discoveries atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/token":
					fmt.Fprint(w, `{"access_token":"test-token","expires_in":3600}`)
				case "/v1/models":
					discoveries.Add(1)
					if r.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("missing discovery token")
					}
					fmt.Fprint(w, `{"data":[{"id":"Claude-hidden"},{"id":"gpt-keep"},{"id":"xclaude-keep"}]}`)
				default:
					t.Errorf("unexpected upstream request: %s", r.URL.Path)
				}
			}))
			defer srv.Close()
			p := New(noHost{})
			defer p.Close()
			cfg := map[string]any{"CLIENT_ID": "id", "CLIENT_SECRET": "secret", "CLIENT_SCOPE": "scope", "TOKEN_URL": srv.URL + "/token", "API_URL": srv.URL + "/v1", "model_prefix": "team/"}
			excludedAlias, allowedAlias, substringAlias := "team/Claude-hidden", "team/gpt-keep", "team/xclaude-keep"
			if configured {
				excludedAlias, allowedAlias, substringAlias = "friendly", "claude-public", "other"
				cfg["models"] = []map[string]string{{"name": "Claude-hidden", "alias": excludedAlias}, {"name": "gpt-keep", "alias": allowedAlias}, {"name": "xclaude-keep", "alias": substringAlias}}
			}
			check := func(prefixes []string, expected []string) {
				t.Helper()
				cfg["models_excluded"] = prefixes
				if _, err := p.Handle("plugin.reconfigure", lifecycle(t, cfg)); err != nil {
					t.Fatal(err)
				}
				r, err := p.runtime()
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 2; i++ {
					result, err := p.Handle("model.static", []byte(`{}`))
					if err != nil {
						t.Fatal(err)
					}
					got := make(map[string]bool)
					for _, model := range result.(ModelResponse).Models {
						got[model.ID] = true
					}
					if len(got) != len(expected) {
						t.Fatalf("models: %v, want %v", got, expected)
					}
					for _, alias := range expected {
						if !got[alias] {
							t.Fatalf("missing alias %q", alias)
						}
					}
					for _, alias := range []string{excludedAlias, allowedAlias, substringAlias} {
						raw, _ := json.Marshal(map[string]string{"RequestedModel": alias})
						route, err := p.Handle("model.route", raw)
						if err != nil || route.(map[string]any)["Handled"] != got[alias] {
							t.Fatalf("route %q: %v %v", alias, route, err)
						}
						for _, format := range []string{"chat-completions", "responses"} {
							request := ExecutorRequest{Model: alias, SourceFormat: format, StreamID: "exclusion-test", Payload: []byte(`{}`)}
							_, _, err := r.prepare(request)
							if got[alias] {
								if err != nil {
									t.Fatal(err)
								}
								continue
							}
							for _, method := range []string{"executor.execute", "executor.execute_stream"} {
								request.Stream = method == "executor.execute_stream"
								raw, _ := json.Marshal(request)
								_, err := p.Handle(method, raw)
								var rpc *RPCError
								if !errors.As(err, &rpc) || rpc.HTTPStatus != 404 {
									t.Fatalf("excluded %q %s: %v", alias, method, err)
								}
							}
						}
					}
				}
			}
			check(nil, []string{excludedAlias, allowedAlias, substringAlias})
			check([]string{" CLAUDE- ", "claude-", ""}, []string{allowedAlias, substringAlias})
			// Even when all explicit entries are excluded, discovery must not take over.
			check([]string{"claude-", "GPT-", "xclaude-"}, nil)
			check([]string{}, []string{excludedAlias, allowedAlias, substringAlias})
			check([]string{"team/", "friendly", "claude-*"}, []string{excludedAlias, allowedAlias, substringAlias})
			if configured && discoveries.Load() != 0 {
				t.Fatal("explicit model list triggered discovery")
			}
		})
	}
}

func TestModelsExcludedMetadata(t *testing.T) {
	for _, field := range registration().Metadata.ConfigFields {
		if field.Name == "models_excluded" {
			if field.Type != "array" {
				t.Fatalf("wrong exclusion field type: %v", field)
			}
			return
		}
	}
	t.Fatal("Edit config metadata lacks models_excluded")
}

func TestModelPrefixLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix *string
		want   string
	}{
		{name: "default", want: "oauth/model"},
		{name: "bare", prefix: stringPointer("oauth"), want: "oauth/model"},
		{name: "trailing slash", prefix: stringPointer("oauth/"), want: "oauth/model"},
		{name: "custom", prefix: stringPointer("team"), want: "team/model"},
		{name: "nested", prefix: stringPointer("team/oauth"), want: "team/oauth/model"},
		{name: "empty", prefix: stringPointer(""), want: "model"},
	} {
		for _, configured := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/configured=%v", tc.name, configured), func(t *testing.T) {
				var discoveries atomic.Int64
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/token":
						fmt.Fprint(w, `{"access_token":"test-token","expires_in":3600}`)
					case "/v1/models":
						discoveries.Add(1)
						fmt.Fprint(w, `{"data":[{"id":"model"}]}`)
					default:
						t.Errorf("unexpected upstream request: %s", r.URL.Path)
					}
				}))
				defer srv.Close()
				p := New(noHost{})
				defer p.Close()
				cfg := map[string]any{"CLIENT_ID": "id", "CLIENT_SECRET": "secret", "CLIENT_SCOPE": "scope", "TOKEN_URL": srv.URL + "/token", "API_URL": srv.URL + "/v1"}
				if tc.prefix != nil {
					cfg["model_prefix"] = *tc.prefix
				}
				want := []string{tc.want}
				if configured {
					cfg["models"] = []map[string]string{{"name": "model"}, {"name": "aliased-model", "alias": "friendly"}}
					want = append(want, "friendly")
				}
				for _, method := range []string{"plugin.register", "plugin.reconfigure"} {
					if _, err := p.Handle(method, lifecycle(t, cfg)); err != nil {
						t.Fatal(err)
					}
					result, err := p.Handle("model.static", []byte(`{}`))
					if err != nil {
						t.Fatal(err)
					}
					models := result.(ModelResponse).Models
					if len(models) != len(want) {
						t.Fatalf("models: %v, want %v", models, want)
					}
					for _, alias := range want {
						found := false
						for _, model := range models {
							found = found || model.ID == alias
						}
						if !found {
							t.Fatalf("missing model %q: %v", alias, models)
						}
						raw, _ := json.Marshal(map[string]string{"RequestedModel": alias})
						route, err := p.Handle("model.route", raw)
						if err != nil || route.(map[string]any)["Handled"] != true {
							t.Fatalf("route %q: %v %v", alias, route, err)
						}
					}
				}
				if configured && discoveries.Load() != 0 {
					t.Fatal("explicit models triggered discovery")
				}
			})
		}
	}
}

func stringPointer(value string) *string { return &value }

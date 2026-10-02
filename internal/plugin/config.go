// Package plugin implements CLIProxyAPI's native plugin RPC contract.
package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"cliproxyapi-oauth/internal/oauth"

	"gopkg.in/yaml.v3"
)

const ID = "openai-oauth"

var Version = "0.1.0"

// Repository is replaced by the release workflow; syepes marks local development builds.
var Repository = "https://github.com/syepes/CLIProxyAPI-openai-oauth"

type ModelConfig struct {
	Name  string `yaml:"name"`
	Alias string `yaml:"alias"`
}
type Config struct {
	ClientID            string         `yaml:"CLIENT_ID"`
	ClientSecret        string         `yaml:"CLIENT_SECRET"`
	ClientScope         string         `yaml:"CLIENT_SCOPE"`
	TokenURL            string         `yaml:"TOKEN_URL"`
	APIURL              string         `yaml:"API_URL"`
	TokenAuthMethod     string         `yaml:"token_auth_method"`
	TokenTimeoutSeconds int            `yaml:"token_timeout_seconds"`
	ModelPrefix         string         `yaml:"model_prefix"`
	Models              []ModelConfig  `yaml:"models"`
	ModelsExcluded      []string       `yaml:"models_excluded"`
	Enabled             bool           `yaml:"enabled"`
	Priority            int            `yaml:"priority"`
	Store               map[string]any `yaml:"store"`
}

func parseConfig(raw []byte) (Config, oauth.Config, error) {
	cfg := Config{Enabled: true, ModelPrefix: "oauth"}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, oauth.Config{}, errors.New("invalid plugin YAML or unsupported configuration field")
	}
	// Treat nonempty prefixes as namespaces while preserving legacy trailing slashes.
	if cfg.ModelPrefix != "" && !strings.HasSuffix(cfg.ModelPrefix, "/") {
		cfg.ModelPrefix += "/"
	}
	cfg.ModelsExcluded = normalizeModelPrefixes(cfg.ModelsExcluded)
	if !cfg.Enabled {
		return cfg, oauth.Config{}, nil
	}
	resolved := oauth.Config{AuthMethod: cfg.TokenAuthMethod, Timeout: time.Duration(cfg.TokenTimeoutSeconds) * time.Second}
	for _, field := range []struct {
		name, raw string
		dest      *string
	}{
		{"CLIENT_ID", cfg.ClientID, &resolved.ClientID},
		{"CLIENT_SECRET", cfg.ClientSecret, &resolved.ClientSecret},
		{"CLIENT_SCOPE", cfg.ClientScope, &resolved.Scope},
		{"TOKEN_URL", cfg.TokenURL, &resolved.TokenURL},
		{"API_URL", cfg.APIURL, &resolved.APIURL},
	} {
		value, err := oauth.Resolve(field.raw, field.name)
		if err != nil {
			return cfg, resolved, fmt.Errorf("%s: %w", field.name, err)
		}
		*field.dest = value
	}
	if err := resolved.Validate(); err != nil {
		return cfg, resolved, err
	}
	seen := make(map[string]bool)
	for i := range cfg.Models {
		m := &cfg.Models[i]
		m.Name = strings.TrimSpace(m.Name)
		m.Alias = strings.TrimSpace(m.Alias)
		if m.Name == "" {
			return cfg, resolved, errors.New("each configured model requires a name")
		}
		if m.Alias == "" {
			m.Alias = cfg.ModelPrefix + m.Name
		}
		if seen[m.Alias] {
			return cfg, resolved, errors.New("model aliases must be unique")
		}
		seen[m.Alias] = true
	}
	return cfg, resolved, nil
}

// normalizeModelPrefixes matches the Copilot plugin's exclusion semantics.
func normalizeModelPrefixes(prefixes []string) []string {
	seen := make(map[string]struct{}, len(prefixes))
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix == "" {
			continue
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out
}

// modelExcluded checks the upstream ID, never the public prefix or alias.
func (c Config) modelExcluded(id string) bool {
	id = strings.ToLower(id)
	for _, prefix := range c.ModelsExcluded {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

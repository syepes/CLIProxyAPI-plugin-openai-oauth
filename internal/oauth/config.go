// Package oauth implements OAuth 2.0 client-credentials token management.
package oauth

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config contains resolved credentials. Never log or serialize it.
type Config struct {
	ClientID     string
	ClientSecret string
	Scope        string
	TokenURL     string
	APIURL       string
	AuthMethod   string
	Timeout      time.Duration
}

// Resolve supports literal values, env:NAME, and file:/absolute/path.
// Credential files must be regular, non-symlink, owner-only files.
func Resolve(value, fallback string) (string, error) {
	if value == "" {
		value = "env:" + fallback
	}
	if name, ok := strings.CutPrefix(value, "env:"); ok {
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(name) {
			return "", errors.New("invalid environment reference")
		}
		v, exists := os.LookupEnv(name)
		if !exists || v == "" {
			return "", errors.New("referenced environment variable is empty or unset")
		}
		return v, nil
	}
	if path, ok := strings.CutPrefix(value, "file:"); ok {
		if !strings.HasPrefix(path, "/") {
			return "", errors.New("credential file path must be absolute")
		}
		before, err := os.Lstat(path)
		if err != nil {
			return "", errors.New("cannot inspect credential file")
		}
		if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
			return "", errors.New("credential file must be regular, not a symlink, and owner-only (0600 or 0400)")
		}
		f, err := os.Open(path)
		if err != nil {
			return "", errors.New("cannot open credential file")
		}
		defer f.Close()
		after, err := f.Stat()
		if err != nil || !os.SameFile(before, after) || after.Mode().Perm()&0077 != 0 {
			return "", errors.New("credential file changed while opening")
		}
		data, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil || len(data) > 65536 {
			return "", errors.New("cannot read credential file or file exceeds 64 KiB")
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return value, nil
}

// ValidateURL permits HTTP only for numeric loopback development URLs.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" {
		return nil, errors.New("must be an absolute URL without userinfo, query, or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("HTTPS is required (HTTP is allowed only for numeric loopback addresses)")
		}
	}
	if strings.ContainsAny(raw, "\r\n\t") {
		return nil, errors.New("URL contains control characters")
	}
	return u, nil
}

func (c *Config) Validate() error {
	for name, v := range map[string]string{"CLIENT_ID": c.ClientID, "CLIENT_SECRET": c.ClientSecret, "CLIENT_SCOPE": c.Scope} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	for name, v := range map[string]string{"TOKEN_URL": c.TokenURL, "API_URL": c.APIURL} {
		if _, err := ValidateURL(v); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if c.AuthMethod == "" {
		c.AuthMethod = "client_secret_post"
	}
	if c.AuthMethod != "client_secret_post" && c.AuthMethod != "client_secret_basic" {
		return errors.New("token_auth_method must be client_secret_post or client_secret_basic")
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Timeout < time.Second || c.Timeout > time.Minute {
		return errors.New("token timeout must be between 1 and 60 seconds")
	}
	c.APIURL = strings.TrimRight(c.APIURL, "/")
	return nil
}

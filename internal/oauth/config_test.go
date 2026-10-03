package oauth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEndpointValidation(t *testing.T) {
	for _, url := range []string{"https://example.com/v1", "http://127.0.0.1:1234/v1", "http://[::1]:1234/token"} {
		if _, err := ValidateURL(url); err != nil {
			t.Fatalf("valid URL rejected: %v", err)
		}
	}
	for _, url := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com?secret=x", "https://example.com#fragment", "//example.com", "https:///token", "file:///tmp/x"} {
		if _, err := ValidateURL(url); err == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
}
func TestCredentialReferences(t *testing.T) {
	t.Setenv("OAUTH_TEST_SECRET", "sensitive")
	if v, err := Resolve("env:OAUTH_TEST_SECRET", ""); err != nil || v != "sensitive" {
		t.Fatal("environment reference failed")
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("sensitive\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if v, err := Resolve("file:"+path, ""); err != nil || v != "sensitive" {
		t.Fatal("file reference failed")
	}
	if runtime.GOOS != "windows" {
		// os.Chmod on Windows only toggles the read-only attribute from the
		// owner-write bit; 0644 keeps that bit set, so this leaves the file's
		// actual access control (and Resolve's acceptance of it) unchanged.
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Resolve("file:"+path, ""); err == nil {
			t.Fatal("world-readable credential accepted")
		}
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		// Creating a symlink on Windows needs Developer Mode or an elevated
		// process (SeCreateSymbolicLinkPrivilege), which hosted CI runners
		// grant inconsistently; this is a platform limitation, not something
		// Resolve controls, so skip rather than fail the build on it.
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlink: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := Resolve("file:"+link, ""); err == nil {
		t.Fatal("credential symlink accepted")
	}
}

func TestConfigInvalidOptions(t *testing.T) {
	base := Config{ClientID: "id", ClientSecret: "secret", Scope: "scope", TokenURL: "https://id.example/token", APIURL: "https://api.example/v1"}
	for _, modify := range []func(*Config){func(c *Config) { c.Scope = "" }, func(c *Config) { c.ClientID = "" }, func(c *Config) { c.ClientSecret = "" }, func(c *Config) { c.APIURL = "file:///tmp" }, func(c *Config) { c.TokenURL = "broken" }, func(c *Config) { c.AuthMethod = "unsupported" }, func(c *Config) { c.Timeout = 1 }} {
		cfg := base
		modify(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := Resolve("env:INVALID NAME", ""); err == nil {
		t.Fatal("invalid environment reference accepted")
	}
	if _, err := Resolve("env:OAUTH_NONEXISTENT_UNIT_TEST_SECRET", ""); err == nil {
		t.Fatal("missing environment reference accepted")
	}
	if _, err := Resolve("file:relative", ""); err == nil {
		t.Fatal("relative file accepted")
	}
	if _, err := Resolve("file:"+filepath.Join(t.TempDir(), "missing"), ""); err == nil {
		t.Fatal("missing file accepted")
	}
}

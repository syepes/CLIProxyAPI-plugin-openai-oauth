package plugin

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"net/http"
	"strings"
)

//go:embed dashboard.html
var dashboardHTML string

func dashboard() ManagementResponse {
	policy := "default-src 'none'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; script-src " + inlineHash("script") + "; style-src " + inlineHash("style")
	return ManagementResponse{StatusCode: 200, Headers: http.Header{"Content-Type": {"text/html; charset=utf-8"}, "Cache-Control": {"no-store"}, "Content-Security-Policy": {policy}, "Referrer-Policy": {"no-referrer"}, "X-Content-Type-Options": {"nosniff"}}, Body: []byte(dashboardHTML)}
}
func inlineHash(tag string) string {
	_, after, _ := strings.Cut(dashboardHTML, "<"+tag+">")
	body, _, _ := strings.Cut(after, "</"+tag+">")
	sum := sha256.Sum256([]byte(body))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

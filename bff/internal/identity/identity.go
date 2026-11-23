// Package identity holds the caller identity for standalone and plugin requests.
//
// Standalone requests use headers set by kube-auth-proxy (or the local Vite
// dev proxy from `oc whoami`). Plugin requests use claims from a validated
// OSAC Keycloak access token.
package identity

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Identity is the authenticated caller and the token forwarded to the backend.
type Identity struct {
	Username string
	Email    string
	Groups   []string
	// ProviderAdmin is the authorization result attached by the authenticator.
	// Standalone callers still derive it from SSAR; plugin callers derive it
	// from the validated OSAC role claims.
	ProviderAdmin bool
	authMode      authMode
	token         string
}

type authMode uint8

const (
	standaloneMode authMode = iota
	pluginMode
)

// Token returns the caller's bearer token, forwarded to the backend.
func (i Identity) Token() string { return i.token }

// String hides the token from logs and error messages.
func (i Identity) String() string {
	return fmt.Sprintf("Identity{user:%q groups:%d token:[REDACTED]}", i.Username, len(i.Groups))
}

// Headers names the proxy headers to read.
type Headers struct {
	User        string
	Email       string
	Groups      string
	Token       string
	TokenPrefix string
}

// Extract builds an Identity from request headers. The token is required; the
// other headers are optional because API clients that send a bearer token
// directly to the proxy may not have them set.
func (h Headers) Extract(header http.Header) (Identity, error) {
	raw := strings.TrimSpace(header.Get(h.Token))
	if raw == "" {
		return Identity{}, fmt.Errorf("missing %s header", h.Token)
	}
	if h.TokenPrefix != "" {
		if !strings.HasPrefix(raw, h.TokenPrefix) {
			return Identity{}, fmt.Errorf("%s header must start with %q", h.Token, h.TokenPrefix)
		}
		raw = strings.TrimSpace(strings.TrimPrefix(raw, h.TokenPrefix))
	}
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return Identity{}, fmt.Errorf("%s header does not contain a valid token", h.Token)
	}
	id := Identity{
		Username: strings.TrimSpace(header.Get(h.User)),
		Email:    strings.TrimSpace(header.Get(h.Email)),
		Groups:   splitGroups(header.Values(h.Groups)),
		authMode: standaloneMode,
		token:    raw,
	}
	return id, nil
}

// NewPlugin constructs the identity for the federated OSAC UI path from
// claims that have already been validated by the OIDC verifier.
func NewPlugin(token, username, email string, groups []string, isOSACAdmin bool) Identity {
	return Identity{
		Username:      username,
		Email:         email,
		Groups:        append([]string(nil), groups...),
		ProviderAdmin: isOSACAdmin,
		authMode:      pluginMode,
		token:         token,
	}
}

// IsPlugin reports whether this identity came from a validated OIDC plugin request.
func (i Identity) IsPlugin() bool { return i.authMode == pluginMode }

// splitGroups accepts repeated headers and comma-separated values.
func splitGroups(values []string) []string {
	var out []string
	for _, v := range values {
		for g := range strings.SplitSeq(v, ",") {
			if g = strings.TrimSpace(g); g != "" {
				out = append(out, g)
			}
		}
	}
	return out
}

type contextKey struct{}

// WithIdentity stores the identity on the context.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext returns the identity stored by WithIdentity.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok && id.token != ""
}

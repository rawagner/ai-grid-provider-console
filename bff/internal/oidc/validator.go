// Package oidc validates OSAC UI access tokens using the configured issuer's
// discovery document and JSON Web Key Set.
package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	maxTokenBytes = 16 << 10
	maxOIDCBytes  = 1 << 20
	keyCacheAge   = 5 * time.Minute
	keyRefreshGap = time.Second
)

// ErrUnavailable means the configured issuer or its signing keys could not be
// reached. Callers should report a temporary service error, not treat it as an
// invalid credential.
var ErrUnavailable = errors.New("OIDC issuer unavailable")

// Config identifies the issuer and the OSAC UI client whose access tokens are
// accepted by the plugin API.
type Config struct {
	IssuerURL  string
	ClientID   string
	CAFile     string
	Insecure   bool
	HTTPClient *http.Client
}

// Principal contains the identity and OSAC role derived from a verified
// access token.
type Principal struct {
	Username    string
	Email       string
	Groups      []string
	IsOSACAdmin bool
}

type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type keySetDocument struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	KeyType  string `json:"kty"`
	KeyID    string `json:"kid"`
	Use      string `json:"use"`
	Alg      string `json:"alg"`
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

type keycloakRealmAccess struct {
	Roles []string `json:"roles"`
}

type accessTokenClaims struct {
	jwt.RegisteredClaims
	AuthorizedParty   string              `json:"azp"`
	PreferredUsername string              `json:"preferred_username"`
	Name              string              `json:"name"`
	Email             string              `json:"email"`
	Groups            []string            `json:"groups"`
	RealmAccess       keycloakRealmAccess `json:"realm_access"`
}

// Validator verifies issuer, signing key, expiry, not-before and the OSAC UI
// client before exposing claims to the API layer.
type Validator struct {
	issuer   string
	clientID string
	jwksURL  string
	http     *http.Client

	mu            sync.Mutex
	keys          map[string]*rsa.PublicKey
	keysExpireAt  time.Time
	lastRefreshAt time.Time
}

// New discovers the issuer and loads its signing keys. It fails closed when
// discovery or the initial key set cannot be fetched.
func New(ctx context.Context, cfg Config) (*Validator, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	if issuer == "" || strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("OIDC issuer URL and client ID are required")
	}
	issuerURL, err := parseTrustedURL("OIDC issuer URL", issuer)
	if err != nil {
		return nil, err
	}
	if issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return nil, errors.New("OIDC issuer URL must not include a query or fragment")
	}

	client := cfg.HTTPClient
	if client == nil {
		client, err = newHTTPClient(cfg.CAFile, cfg.Insecure)
		if err != nil {
			return nil, err
		}
	}
	v := &Validator{
		issuer:   issuer,
		clientID: strings.TrimSpace(cfg.ClientID),
		http:     client,
	}

	var discovery discoveryDocument
	if err := v.getJSON(ctx, issuer+"/.well-known/openid-configuration", &discovery); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	discoveredIssuer := strings.TrimRight(strings.TrimSpace(discovery.Issuer), "/")
	if discoveredIssuer != issuer {
		return nil, fmt.Errorf("OIDC discovery issuer %q does not match configured issuer", discoveredIssuer)
	}
	jwksURI := strings.TrimSpace(discovery.JWKSURI)
	if _, err := parseTrustedURL("OIDC JWKS URL", jwksURI); err != nil {
		return nil, err
	}
	jwksURL, _ := url.Parse(jwksURI)
	if jwksURL.RawQuery != "" || jwksURL.Fragment != "" {
		return nil, errors.New("OIDC JWKS URL must not include a query or fragment")
	}
	v.jwksURL = jwksURI
	if err := v.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("load OIDC signing keys: %w", err)
	}
	return v, nil
}

// Validate verifies a bearer token and returns the identity claims used by
// the plugin API. OSAC's admin role follows the same mapping as OSAC UI:
// realm role cloud-provider-admin or group admins.
func (v *Validator) Validate(ctx context.Context, raw string) (Principal, error) {
	if strings.TrimSpace(raw) == "" || len(raw) > maxTokenBytes || strings.ContainsAny(raw, " \t\r\n") {
		return Principal{}, errors.New("invalid access token")
	}
	claims := &accessTokenClaims{}
	var keyLookupErr error
	token, err := jwt.ParseWithClaims(
		raw,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodRS256 {
				return nil, errors.New("unsupported access token signing method")
			}
			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, errors.New("access token has no signing key ID")
			}
			key, err := v.publicKey(ctx, kid)
			if errors.Is(err, ErrUnavailable) {
				keyLookupErr = err
			}
			return key, err
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil || token == nil || !token.Valid {
		if keyLookupErr != nil {
			return Principal{}, keyLookupErr
		}
		if errors.Is(err, ErrUnavailable) {
			return Principal{}, err
		}
		return Principal{}, errors.New("invalid or expired access token")
	}
	if claims.Subject == "" || (claims.AuthorizedParty != v.clientID && !contains(claims.Audience, v.clientID)) {
		return Principal{}, errors.New("access token was not issued to the OSAC UI client")
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Name
	}
	if username == "" {
		username = claims.Subject
	}
	groups := append([]string(nil), claims.Groups...)
	if groups == nil {
		groups = []string{}
	}
	return Principal{
		Username:    username,
		Email:       claims.Email,
		Groups:      groups,
		IsOSACAdmin: contains(groups, "admins") || contains(claims.RealmAccess.Roles, "cloud-provider-admin"),
	}, nil
}

func (v *Validator) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	key, found := v.keys[kid]
	needsRefresh := now.After(v.keysExpireAt) || (!found && now.Sub(v.lastRefreshAt) >= keyRefreshGap)
	if needsRefresh {
		if err := v.refreshKeysLocked(ctx); err != nil {
			if found {
				return key, nil
			}
			return nil, fmt.Errorf("%w: refresh signing keys", ErrUnavailable)
		}
		key, found = v.keys[kid]
	}
	if !found {
		return nil, errors.New("access token signing key was not found")
	}
	return key, nil
}

func (v *Validator) refreshKeys(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.refreshKeysLocked(ctx)
}

func (v *Validator) refreshKeysLocked(ctx context.Context) error {
	var document keySetDocument
	if err := v.getJSON(ctx, v.jwksURL, &document); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, jwk := range document.Keys {
		if jwk.KeyType != "RSA" || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != "RS256") || jwk.KeyID == "" {
			continue
		}
		key, err := rsaKey(jwk)
		if err != nil {
			continue
		}
		keys[jwk.KeyID] = key
	}
	if len(keys) == 0 {
		return errors.New("issuer returned no usable RS256 signing keys")
	}
	v.keys = keys
	v.keysExpireAt = time.Now().Add(keyCacheAge)
	v.lastRefreshAt = time.Now()
	return nil
}

func (v *Validator) getJSON(ctx context.Context, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	response, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: request failed", ErrUnavailable)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: endpoint returned HTTP %d", ErrUnavailable, response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxOIDCBytes)).Decode(target); err != nil {
		return fmt.Errorf("decode OIDC response: %w", err)
	}
	return nil
}

func rsaKey(jwk jsonWebKey) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
	if err != nil || len(modulus) == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	exponent, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e.Int64())}, nil
}

func newHTTPClient(caFile string, insecure bool) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		// Explicit local-development option matching OIDC_TLS_INSECURE in OSAC UI.
		transport.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- opt-in dev-only override
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read OIDC CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("OIDC CA file %s holds no certificates", caFile)
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, nil
}

func parseTrustedURL(name, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return nil, fmt.Errorf("%s must be an absolute HTTP(S) URL without user information", name)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("%s must use HTTPS except for loopback development", name)
	}
	return u, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

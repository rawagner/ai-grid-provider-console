// Package api wires HTTP routes, middleware and handlers.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/backend"
	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/config"
	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/hub"
	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/identity"
	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/oidc"
	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/perses"
	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/relay"
)

// Version is set at build time with -ldflags "-X ...api.Version=<v>".
var Version = "dev"

// APIPrefix is the path prefix for JSON endpoints.
const APIPrefix = "/api/v1"

// App holds the dependencies shared by all handlers.
type App struct {
	cfg     config.Config
	logger  *slog.Logger
	backend *backend.Client
	// hub answers the provider-admin access review with the caller's token.
	hub *hub.Client
	// oidc validates access tokens when this BFF runs in plugin mode.
	oidc     *oidc.Validator
	isPlugin bool
	headers  identity.Headers
	// perses relays the Monitoring page to the hub's Perses; nil when it is off.
	perses *perses.Relay
	// connect relays the browser's Connect calls to the backend's own RPCs; nil when it is off.
	connect *relay.Relay
}

// NewApp assembles the application and configures OIDC validation in plugin mode.
func NewApp(cfg config.Config, logger *slog.Logger, client *backend.Client, hubClient *hub.Client) (*App, error) {
	app := &App{
		cfg:      cfg,
		logger:   logger,
		backend:  client,
		hub:      hubClient,
		isPlugin: cfg.PluginEnabled(),
		headers: identity.Headers{
			User:        cfg.AuthUserHeader,
			Email:       cfg.AuthEmailHeader,
			Groups:      cfg.AuthGroupsHeader,
			Token:       cfg.AuthTokenHeader,
			TokenPrefix: cfg.AuthTokenPrefix,
		},
	}
	if app.isPlugin {
		validator, err := oidc.New(context.Background(), oidc.Config{
			IssuerURL: cfg.OIDCIssuerURL,
			ClientID:  cfg.OIDCClientID,
			CAFile:    cfg.OIDCCAFile,
			Insecure:  cfg.OIDCTLSInsecure,
		})
		if err != nil {
			return nil, fmt.Errorf("configure plugin authentication: %w", err)
		}
		app.oidc = validator
	}
	return app, nil
}

// WithPerses turns on the Monitoring page's relay to the hub's Perses.
func (a *App) WithPerses(p *perses.Relay) *App {
	a.perses = p
	return a
}

// WithRelay turns on the relay of Connect calls (/ai_grid.v1.*) to the backend.
func (a *App) WithRelay(r *relay.Relay) *App {
	a.connect = r
	return a
}

// Handler selects the auth middleware and static files for the BFF's single listener.
func (a *App) Handler() http.Handler {
	authenticate := a.requireIdentity
	authorize := a.requireProviderAdmin
	includePerses := true
	var assets http.Handler
	if a.isPlugin {
		authenticate = a.requireOIDCIdentity
		authorize = a.requireOSACAdmin
		includePerses = false
	}
	if a.cfg.StaticAssetsDir != "" {
		// config.Parse refuses a tile URL without a source; a Config built
		// otherwise gets a map without its tiles, not a wider policy.
		tiles, _ := config.MapTileSource(a.cfg.MapTileURL)
		assets = newSPAHandler(a.cfg.StaticAssetsDir, pagePolicy(tiles), a.isPlugin)
	}
	return a.handler(authenticate, authorize, assets, includePerses)
}

// handler wires routes shared by both auth modes.
func (a *App) handler(authenticate, authorize func(http.Handler) http.Handler, assets http.Handler, includePerses bool) http.Handler {
	api := http.NewServeMux()
	a.registerRoutes(api)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthcheck", a.healthcheck)
	root.HandleFunc("GET /readyz", a.readyz)
	root.Handle(APIPrefix+"/", authenticate(authorize(api)))
	if includePerses {
		// The Monitoring page's Perses calls use the same caller checks as the API.
		root.Handle(perses.Prefix+"/", authenticate(authorize(http.HandlerFunc(a.relayPerses))))
	}
	if assets != nil {
		root.Handle("/", assets)
	}

	// Connect paths have no trailing slash, so route them before ServeMux.
	connect := authenticate(authorize(http.HandlerFunc(a.relayConnect)))
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if relay.Handles(r.URL.Path) {
			connect.ServeHTTP(w, r)
			return
		}
		root.ServeHTTP(w, r)
	})
	return a.recoverPanic(a.logRequests(compress(routes)))
}

// relayPerses forwards an allowed Perses call with the caller's own token (perses.Relay decides
// which calls are allowed). Without a Perses server configured, Monitoring is off.
func (a *App) relayPerses(w http.ResponseWriter, r *http.Request) {
	if a.perses == nil {
		perses.WriteError(w, http.StatusNotFound, "monitoring is not configured on this console")
		return
	}
	id, _ := identity.FromContext(r.Context())
	a.perses.ServeHTTP(w, r.WithContext(perses.WithToken(r.Context(), id.Token())))
}

// relayConnect forwards a Connect call to the backend with the caller's identity (relay.Relay
// decides which calls pass).
func (a *App) relayConnect(w http.ResponseWriter, r *http.Request) {
	if a.connect == nil {
		relay.WriteError(w, http.StatusNotFound, "the Connect relay is not configured on this console")
		return
	}
	a.connect.ServeHTTP(w, r)
}

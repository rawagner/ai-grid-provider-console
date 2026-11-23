package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/hub"
	"github.com/ai-grid-cloud/ai-grid-provider-console/bff/internal/identity"
)

// User is the signed-in caller as the UI shows it.
type User struct {
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups"`
	// IsProviderAdmin tells the UI whether to offer provider-admin actions. It
	// comes from the hub's SSAR in standalone mode, or the verified OSAC admin
	// claims in plugin mode. The BFF also gates API calls and relays with the
	// corresponding check because the backend does not authorize callers yet.
	IsProviderAdmin bool `json:"isProviderAdmin"`
}

// getUser answers GET /api/v1/user. Standalone identity comes from proxy
// headers and SSAR; plugin identity and its admin role come from the verified
// OSAC access token.
func (a *App) getUser(w http.ResponseWriter, r *http.Request) {
	id, _ := identity.FromContext(r.Context())
	groups := id.Groups
	if groups == nil {
		groups = []string{}
	}
	isAdmin := id.ProviderAdmin
	if !id.IsPlugin() {
		var err error
		isAdmin, err = a.hub.CanI(r.Context(), id.Token(), hub.ProviderAdminCheck)
		if err != nil {
			if errors.Is(err, hub.ErrUnauthorized) {
				a.respondError(w, r, Errorf(http.StatusUnauthorized, "the hub rejected the credentials; log in again"))
				return
			}
			a.respondError(w, r, fmt.Errorf("%w: provider-admin check for %s: %w", errHub, id.Username, err))
			return
		}
	}
	writeData(w, http.StatusOK, User{
		Username:        id.Username,
		Email:           id.Email,
		Groups:          groups,
		IsProviderAdmin: isAdmin,
	})
}

package api

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// assetsPrefix and pluginAssetsPrefix are Vite's hashed asset directories.
// Their files can be cached for good; root files such as index.html, the plugin
// descriptor and federation entry keep stable names and are revalidated.
const assetsPrefix = "/assets/"
const pluginURLPrefix = "/plugins/ai-grid-provider-console/"
const pluginAssetsPrefix = pluginURLPrefix + "assets/"

// spaHandler serves the built frontend and falls back to index.html for client
// routes so deep links work.
type spaHandler struct {
	dir        string
	pluginOnly bool
	files      http.Handler
	// policy is the Content-Security-Policy of every file served (pagePolicy).
	policy string
}

func newSPAHandler(dir, policy string, pluginOnly bool) http.Handler {
	return &spaHandler{dir: dir, files: http.FileServer(http.Dir(dir)), policy: policy, pluginOnly: pluginOnly}
}

// pagePolicy is the Content-Security-Policy of the console's pages, so that
// markup some component puts into a page (a chart's HTML tooltip, a panel's
// rendered text) can only be markup: the bundle's own files are the only
// scripts, with no inline script, inline event handler, javascript: URL or
// eval; no embedded objects; no <base> to move the page's relative URLs elsewhere; no
// form posting off the console; and no other site framing it. Each directive
// allows what the built console uses, and nothing it doesn't:
//
//   - script-src 'self': the module scripts Vite writes under /assets/.
//     Nothing in the bundle evaluates strings (zod is told not to probe for
//     it, src/validation/zod.ts).
//   - style-src 'unsafe-inline': the Monitoring page's Perses components
//     insert <style> elements at run time (Emotion for MUI, goober,
//     react-colorful), with no nonce to give them; without it their panels do
//     not render. The other pages set styles only through the DOM, which a
//     policy does not restrict. A style cannot run script.
//   - img-src data: index.html's empty favicon (data:,), which keeps the
//     browser from asking for /favicon.ico; plus the map's tile server when
//     MAP_TILE_URL names one (config.MapTileSource).
//   - font-src, connect-src 'self': the bundled fonts; the API, the Perses
//     relay and the Connect relay, all on the console's origin.
//   - object-src 'none', base-uri 'none': no embedded object content, and index.html
//     has no <base>.
//   - form-action 'self': a form submits to the console only.
//   - frame-ancestors 'none': the console must not be framed, not even by
//     another app under the cluster's *.apps domain, which is same-site, so
//     SameSite=Lax on the proxy's cookie does not stop it (clickjacking an
//     admin's session).
//
// default-src 'self' covers what is left (workers, frames, media), none of
// which the console uses.
func pagePolicy(tileSource string) string {
	img := "img-src 'self' data:"
	if tileSource != "" {
		img += " " + tileSource
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		img,
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
}

// setPageSecurityHeaders is sent with every file of the SPA: the page policy
// (pagePolicy), X-Frame-Options for browsers that predate frame-ancestors,
// nosniff so a browser never runs a file as another type than the one sent,
// and a referrer that stays on the console.
func setPageSecurityHeaders(h http.Header, policy string) {
	h.Set("Content-Security-Policy", policy)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
}

func (s *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clean := path.Clean("/" + r.URL.Path)
	r.URL.Path = clean // the file server and ServeFile see only the cleaned path
	isPluginAsset := clean == "/osac-plugin.json" ||
		clean == "/mf-manifest.json" || strings.HasPrefix(clean, "/plugins/")
	if s.pluginOnly && !isPluginAsset {
		http.NotFound(w, r)
		return
	}
	if isPluginAsset {
		// Federated remotes are ES modules fetched by the OSAC UI from another
		// origin. These files contain no user data or API responses.
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	setPageSecurityHeaders(w.Header(), s.policy)
	targetPath := strings.TrimPrefix(clean, "/")
	if s.pluginOnly {
		// The plugin's public URL is namespaced, but its selected Vite build lives at dist root.
		if pluginPath, ok := strings.CutPrefix(clean, pluginURLPrefix); ok {
			targetPath = pluginPath
			r.URL.Path = "/" + pluginPath
		}
	}
	target := filepath.Join(s.dir, filepath.FromSlash(targetPath))
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		if strings.HasPrefix(clean, assetsPrefix) || strings.HasPrefix(clean, pluginAssetsPrefix) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		s.files.ServeHTTP(w, r)
		return
	}
	if s.pluginOnly {
		http.NotFound(w, r)
		return
	}
	if strings.Contains(path.Base(clean), ".") && clean != "/" {
		// A missing file with an extension is a real 404, not a client route.
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, filepath.Join(s.dir, "index.html"))
}

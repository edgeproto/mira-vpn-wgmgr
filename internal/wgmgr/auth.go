package wgmgr

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AdminAuthHandler wraps inner and enforces a shared secret on mutating peer
// routes when adminToken is non-empty. If adminToken is empty, inner is
// returned unchanged (local dev).
//
// Unauthenticated routes: everything except POST /v1/peers and
// DELETE /v1/peers/{id} (e.g. GET /health for load balancers).
//
// Accepted credentials (either matches adminToken):
//   - Authorization: Bearer <token>
//   - X-Mira-Token: <token>
func AdminAuthHandler(adminToken string, inner http.Handler) http.Handler {
	if adminToken == "" {
		return inner
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresPeerAdminAuth(r) {
			inner.ServeHTTP(w, r)
			return
		}
		if !adminTokenMatches(r, adminToken) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		inner.ServeHTTP(w, r)
	})
}

func requiresPeerAdminAuth(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost:
		return r.URL.Path == "/v1/peers"
	case http.MethodDelete:
		return strings.HasPrefix(r.URL.Path, "/v1/peers/")
	default:
		return false
	}
}

func adminTokenMatches(r *http.Request, want string) bool {
	if got, ok := bearerToken(r); ok && constantTimeStringEq(got, want) {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("X-Mira-Token"))
	return got != "" && constantTimeStringEq(got, want)
}

func bearerToken(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return "", false
	}
	lower := strings.ToLower(raw)
	const prefix = "bearer "
	if !strings.HasPrefix(lower, prefix) {
		return "", false
	}
	rest := strings.TrimSpace(raw[len(prefix):])
	if rest == "" {
		return "", false
	}
	return rest, true
}

func constantTimeStringEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

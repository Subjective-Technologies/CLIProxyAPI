package management

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SessionCookieName is the browser cookie set by Sign in to CLIProxy.
const SessionCookieName = "cpa_session"

type managementSession struct {
	userID  string
	company string
	expires time.Time
}

// OpenSession stores a management session and returns its cookie value.
func (h *Handler) OpenSession(userID, company string, expires time.Time) (string, error) {
	if h == nil {
		return "", errors.New("management handler is nil")
	}
	if !expires.After(time.Now()) {
		return "", errors.New("session expiry is in the past")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(buf)
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	if h.sessions == nil {
		h.sessions = make(map[string]managementSession)
	}
	h.sessions[id] = managementSession{
		userID:  strings.TrimSpace(userID),
		company: strings.TrimSpace(company),
		expires: expires,
	}
	return id, nil
}

// CloseSession forgets a management session. A missing id is ignored.
func (h *Handler) CloseSession(id string) {
	if h == nil || id == "" {
		return
	}
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	delete(h.sessions, id)
}

// ValidSession reports whether the request carries a live management session.
// Remote clients still need allow-remote.
func (h *Handler) ValidSession(c *gin.Context, localClient bool) bool {
	if h == nil || c == nil || c.Request == nil {
		return false
	}
	id, err := c.Cookie(SessionCookieName)
	if err != nil || id == "" {
		return false
	}
	if !localClient && !h.remoteManagementAllowed() {
		return false
	}
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	session, ok := h.sessions[id]
	if !ok || !time.Now().Before(session.expires) {
		delete(h.sessions, id)
		return false
	}
	return true
}

// StartFirebaseSession checks the Firebase identity and opens a session that
// lasts until the token expires, at most one hour.
func (h *Handler) StartFirebaseSession(clientIP string, localClient bool, userID, company, token string) (string, time.Time, int, string) {
	expires, ok, status, msg := h.authenticateFirebase(clientIP, localClient, userID, company, token, time.Now())
	if !ok {
		return "", time.Time{}, status, msg
	}
	id, err := h.OpenSession(userID, company, expires)
	if err != nil {
		return "", time.Time{}, http.StatusInternalServerError, "failed to start session"
	}
	return id, expires, 0, ""
}

func (h *Handler) remoteManagementAllowed() bool {
	if h == nil {
		return false
	}
	if h.allowRemoteOverride {
		return true
	}
	return h.cfg != nil && h.cfg.RemoteManagement.AllowRemote
}

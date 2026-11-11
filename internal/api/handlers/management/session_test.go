package management

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestStartFirebaseSessionRequiresProjectID(t *testing.T) {
	t.Setenv("FIREBASE_PROJECT_ID", "")
	t.Setenv("CLIPROXY_COMPANY_NAME", "acme")
	h := &Handler{cfg: configForSessionTest(), failedAttempts: map[string]*attemptInfo{}}
	_, _, status, msg := h.StartFirebaseSession("127.0.0.1", true, "user-123", "acme", "not-a-jwt")
	if status != http.StatusForbidden || msg != "firebase project is not configured" {
		t.Fatalf("status=%d msg=%q", status, msg)
	}
}

func TestStartFirebaseSessionOpensCookieSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CLIPROXY_COMPANY_NAME", "acme")
	t.Setenv("FIREBASE_PROJECT_ID", "test-project")
	key := testRSAKey(t)
	issued := time.Now().UTC().Truncate(time.Second)
	token := testFirebaseToken(t, key, "kid-1", "test-project", "user-123", issued)
	firebaseCerts.mu.Lock()
	previousFetch := firebaseCerts.fetch
	previousKeys := firebaseCerts.byKID
	previousFetched := firebaseCerts.fetched
	firebaseCerts.fetch = func() (map[string]*rsa.PublicKey, error) {
		return map[string]*rsa.PublicKey{"kid-1": &key.PublicKey}, nil
	}
	firebaseCerts.byKID = nil
	firebaseCerts.fetched = time.Time{}
	firebaseCerts.mu.Unlock()
	t.Cleanup(func() {
		firebaseCerts.mu.Lock()
		firebaseCerts.fetch = previousFetch
		firebaseCerts.byKID = previousKeys
		firebaseCerts.fetched = previousFetched
		firebaseCerts.mu.Unlock()
	})

	h := &Handler{cfg: configForSessionTest(), failedAttempts: map[string]*attemptInfo{}}
	id, expires, status, msg := h.StartFirebaseSession("127.0.0.1", true, "user-123", "acme", token)
	if status != 0 || msg != "" || id == "" {
		t.Fatalf("session status=%d msg=%q id=%q", status, msg, id)
	}
	if expires.Before(issued.Add(59*time.Minute)) || expires.After(issued.Add(time.Hour+time.Second)) {
		t.Fatalf("expires %s", expires)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
	ctx.Request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: id})
	if !h.ValidSession(ctx, true) {
		t.Fatal("expected the firebase login to open a valid session")
	}

	_, _, badStatus, badMsg := h.StartFirebaseSession("127.0.0.1", true, "user-123", "other", token)
	if badStatus != http.StatusForbidden || badMsg != "company name does not match this server" {
		t.Fatalf("status=%d msg=%q", badStatus, badMsg)
	}
}

func configForSessionTest() *config.Config {
	return &config.Config{}
}

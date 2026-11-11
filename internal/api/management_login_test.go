package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
)

func attachManagementSession(t *testing.T, h *management.Handler, req *http.Request) {
	t.Helper()
	if req.RemoteAddr == "" {
		req.RemoteAddr = "127.0.0.1:1234"
	}
	id, err := h.OpenSession("test-user", "test-company", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: management.SessionCookieName, Value: id})
}

func TestManagementHTMLRequiresFirebaseSession(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	t.Setenv("CLIPROXY_COMPANY_NAME", "acme")
	t.Setenv("FIREBASE_PROJECT_ID", "test-project")
	staticDir := t.TempDir()
	t.Setenv("MANAGEMENT_STATIC_PATH", staticDir)
	panel := "<html><head><title>panel</title></head><body>management app</body></html>"
	if err := os.WriteFile(filepath.Join(staticDir, "management.html"), []byte(panel), 0o600); err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t)

	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/management.html", nil)
	loginReq.Host = "127.0.0.1:8080"
	server.engine.ServeHTTP(login, loginReq)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", login.Code, login.Body.String())
	}
	for _, want := range []string{"Sign in to CLIProxy", "User id", "Firebase token", "Company name", `value="acme"`} {
		if !strings.Contains(login.Body.String(), want) {
			t.Fatalf("login page missing %q", want)
		}
	}
	if strings.Contains(login.Body.String(), "cpa-firebase-boot") || strings.Contains(login.Body.String(), "management app") {
		t.Fatal("login page still injects the old panel boot script")
	}
	if strings.Contains(login.Body.String(), "AIza") || strings.Contains(login.Body.String(), "firebase.initializeApp") {
		t.Fatal("login page embedded firebase project data")
	}

	denied := httptest.NewRecorder()
	deniedReq := httptest.NewRequest(http.MethodPost, "/management/session", strings.NewReader(`{"user_id":"user","firebase_token":"nope","company_name":"acme"}`))
	deniedReq.Header.Set("Content-Type", "application/json")
	deniedReq.RemoteAddr = "127.0.0.1:1234"
	deniedReq.Host = "127.0.0.1:8080"
	server.engine.ServeHTTP(denied, deniedReq)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d body=%s", denied.Code, denied.Body.String())
	}

	panelReq := httptest.NewRequest(http.MethodGet, "/management.html", nil)
	panelReq.Host = "127.0.0.1:8080"
	attachManagementSession(t, server.mgmt, panelReq)
	panelRR := httptest.NewRecorder()
	server.engine.ServeHTTP(panelRR, panelReq)
	if panelRR.Code != http.StatusOK {
		t.Fatalf("panel status = %d body=%s", panelRR.Code, panelRR.Body.String())
	}
	body := panelRR.Body.String()
	if !strings.Contains(body, "management app") || !strings.Contains(body, `id="cpa-session"`) {
		t.Fatalf("panel was not served with the session prelude: %s", body)
	}
	if strings.Contains(body, "Sign in to CLIProxy") || strings.Contains(body, "XMLHttpRequest.prototype") {
		t.Fatal("panel response still contains the injected sign-in form")
	}
	for _, want := range []string{panelSentinelKey, panelAuthRecord, panelStorageKey, "enc::v2::"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel prelude missing %q", want)
		}
	}
	plain, err := panelAuthPlain("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	stored := obfuscatePanelStorage("127.0.0.1:8080", plain)
	if got := deobfuscatePanelStorage("127.0.0.1:8080", stored); got != plain {
		t.Fatalf("panel storage round trip = %q", got)
	}

	configReq := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
	configReq.Header.Set("Authorization", "Bearer test-management-key")
	configRR := httptest.NewRecorder()
	server.engine.ServeHTTP(configRR, configReq)
	if configRR.Code != http.StatusUnauthorized {
		t.Fatalf("management key status = %d body=%s", configRR.Code, configRR.Body.String())
	}
	attachManagementSession(t, server.mgmt, configReq)
	configRR = httptest.NewRecorder()
	server.engine.ServeHTTP(configRR, configReq)
	if configRR.Code != http.StatusOK {
		t.Fatalf("session status = %d body=%s", configRR.Code, configRR.Body.String())
	}
}

func deobfuscatePanelStorage(host, value string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "enc::v2::"))
	if err != nil {
		return ""
	}
	key := []byte(panelStorageKey + "|" + host)
	for i := range raw {
		raw[i] ^= key[i%len(key)]
	}
	return string(raw)
}

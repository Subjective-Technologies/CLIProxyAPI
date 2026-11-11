package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
)

const (
	panelSentinelKey = "cliproxy-session"
	panelStorageKey  = "cli-proxy-api-webui::secure-storage"
	panelAuthRecord  = "cli-proxy-auth"
)

func googleSignInHosts() []string {
	hosts := []string{"localhost"}
	if project := strings.TrimSpace(os.Getenv("FIREBASE_PROJECT_ID")); project != "" {
		hosts = append(hosts, project+".firebaseapp.com", project+".web.app")
	}
	for _, item := range strings.Split(os.Getenv("CLIPROXY_GOOGLE_SIGNIN_HOSTS"), ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			hosts = append(hosts, item)
		}
	}
	return hosts
}

func firebaseWebConfig() (apiKey, authDomain, projectID string) {
	projectID = strings.TrimSpace(os.Getenv("FIREBASE_PROJECT_ID"))
	apiKey = strings.TrimSpace(os.Getenv("FIREBASE_API_KEY"))
	authDomain = strings.TrimSpace(os.Getenv("FIREBASE_AUTH_DOMAIN"))
	if authDomain == "" && projectID != "" {
		authDomain = projectID + ".firebaseapp.com"
	}
	return apiKey, authDomain, projectID
}

func localManagementClient(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}

func (s *Server) postManagementSession(c *gin.Context) {
	if s == nil || s.mgmt == nil || s.cfg == nil || s.cfg.Home.Enabled || s.cfg.RemoteManagement.DisableControlPanel {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	userID, company, token, next := readManagementLogin(c)
	clientIP := c.ClientIP()
	id, expires, status, msg := s.mgmt.StartFirebaseSession(clientIP, localManagementClient(clientIP), userID, company, token)
	if status != 0 {
		writeManagementLoginFailure(c, status, msg)
		return
	}
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(management.SessionCookieName, id, maxAge, "/", "", requestIsHTTPS(c), true)
	next = allowedManagementNext(next)
	if wantsManagementJSON(c) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "next": next})
		return
	}
	c.Redirect(http.StatusSeeOther, next)
}

func (s *Server) postManagementLogout(c *gin.Context) {
	if c == nil {
		return
	}
	if s != nil && s.mgmt != nil {
		if id, err := c.Cookie(management.SessionCookieName); err == nil {
			s.mgmt.CloseSession(id)
		}
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(management.SessionCookieName, "", -1, "/", "", requestIsHTTPS(c), true)
	c.Status(http.StatusNoContent)
}

func readManagementLogin(c *gin.Context) (userID, company, token, next string) {
	if c == nil || c.Request == nil {
		return "", "", "", ""
	}
	if strings.Contains(strings.ToLower(c.GetHeader("Content-Type")), "application/json") {
		var body struct {
			UserID  string `json:"user_id"`
			Token   string `json:"firebase_token"`
			Company string `json:"company_name"`
			Next    string `json:"next"`
		}
		decoder := json.NewDecoder(io.LimitReader(c.Request.Body, 1<<16))
		if err := decoder.Decode(&body); err != nil {
			return "", "", "", ""
		}
		return body.UserID, body.Company, body.Token, body.Next
	}
	return c.PostForm("user_id"), c.PostForm("company_name"), c.PostForm("firebase_token"), c.PostForm("next")
}

func wantsManagementJSON(c *gin.Context) bool {
	if c == nil {
		return false
	}
	if strings.Contains(strings.ToLower(c.GetHeader("Content-Type")), "application/json") {
		return true
	}
	accept := strings.ToLower(c.GetHeader("Accept"))
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

func writeManagementLoginFailure(c *gin.Context, status int, msg string) {
	if wantsManagementJSON(c) {
		c.JSON(status, gin.H{"error": msg})
		return
	}
	page, err := renderManagementLogin(c, msg)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Data(status, "text/html; charset=utf-8", page)
}

func allowedManagementNext(raw string) string {
	if strings.TrimSpace(raw) == "/management.html?safe-mode=configure" {
		return "/management.html?safe-mode=configure"
	}
	return "/management.html"
}

func managementNext(c *gin.Context) string {
	if c != nil && c.Query("safe-mode") == "configure" {
		return "/management.html?safe-mode=configure"
	}
	return "/management.html"
}

func requestIsHTTPS(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	if c.Request.TLS != nil {
		return true
	}
	proto := c.GetHeader("X-Forwarded-Proto")
	if i := strings.IndexByte(proto, ','); i >= 0 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

func requestHostname(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func googleSignInAllowed(hostport string) bool {
	host := requestHostname(hostport)
	for _, allowed := range googleSignInHosts() {
		if strings.EqualFold(allowed, host) {
			return true
		}
	}
	return false
}

func panelCompanyName() string {
	if name := strings.TrimSpace(os.Getenv("CLIPROXY_COMPANY_NAME")); name != "" {
		return name
	}
	body, err := os.ReadFile("/company_name")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

type managementLoginData struct {
	Company    string
	Error      string
	Next       string
	Google     bool
	Hosts      template.JS
	APIKey     string
	AuthDomain string
	ProjectID  string
}

func renderManagementLogin(c *gin.Context, message string) ([]byte, error) {
	host := ""
	if c != nil && c.Request != nil {
		host = c.Request.Host
	}
	hosts, err := json.Marshal(googleSignInHosts())
	if err != nil {
		return nil, err
	}
	apiKey, authDomain, projectID := firebaseWebConfig()
	var buf bytes.Buffer
	err = managementLoginTemplate.Execute(&buf, managementLoginData{
		Company:    panelCompanyName(),
		Error:      message,
		Next:       managementNext(c),
		Google:     googleSignInAllowed(host) && apiKey != "" && projectID != "",
		Hosts:      template.JS(hosts),
		APIKey:     apiKey,
		AuthDomain: authDomain,
		ProjectID:  projectID,
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func panelAuthPlain(origin string) (string, error) {
	payload, err := json.Marshal(struct {
		APIBase          string  `json:"apiBase"`
		ManagementKey    string  `json:"managementKey"`
		RememberPassword bool    `json:"rememberPassword"`
		ServerVersion    *string `json:"serverVersion"`
		ServerBuildDate  *string `json:"serverBuildDate"`
	}{
		APIBase:          origin,
		ManagementKey:    panelSentinelKey,
		RememberPassword: true,
	})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func obfuscatePanelStorage(host, plain string) string {
	key := []byte(panelStorageKey + "|" + host)
	data := []byte(plain)
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return "enc::v2::" + base64.StdEncoding.EncodeToString(out)
}

func panelSessionPrelude() []byte {
	return []byte(`<script id="cpa-session">` +
		`(function () {` +
		`var host = location.host;` +
		`var key = new TextEncoder().encode("` + panelStorageKey + `|" + host);` +
		`var plain = JSON.stringify({apiBase: location.protocol + "//" + host, managementKey: "` + panelSentinelKey + `", rememberPassword: true, serverVersion: null, serverBuildDate: null});` +
		`var data = new TextEncoder().encode(plain);` +
		`var out = "";` +
		`for (var i = 0; i < data.length; i++) out += String.fromCharCode(data[i] ^ key[i % key.length]);` +
		`localStorage.setItem("` + panelAuthRecord + `", "enc::v2::" + btoa(out));` +
		`localStorage.setItem("isLoggedIn", "true");` +
		`var remove = localStorage.removeItem.bind(localStorage);` +
		`localStorage.removeItem = function (name) {` +
		`remove(name);` +
		`if (name !== "isLoggedIn") return;` +
		`fetch("/management/logout", {method: "POST", keepalive: true, credentials: "same-origin"}).finally(function () {` +
		`location.replace(location.pathname + location.search);` +
		`});};})();` +
		`</script>`)
}

func insertPanelSessionPrelude(body []byte) ([]byte, error) {
	if bytes.Contains(body, []byte(`id="cpa-session"`)) {
		return body, nil
	}
	script := panelSessionPrelude()
	needle := []byte("<head>")
	at := bytes.Index(body, needle)
	if at < 0 {
		out := make([]byte, 0, len(script)+1+len(body))
		out = append(out, script...)
		out = append(out, '\n')
		out = append(out, body...)
		return out, nil
	}
	out := make([]byte, 0, len(body)+len(script)+1)
	out = append(out, body[:at]...)
	out = append(out, []byte("<head>\n")...)
	out = append(out, script...)
	out = append(out, body[at+len(needle):]...)
	return out, nil
}

var managementLoginTemplate = template.Must(template.New("management-login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to CLIProxy</title>
<style>
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #141414; color: #f5f5f5; font: 16px/1.5 sans-serif; }
  form { width: min(420px, calc(100% - 32px)); display: flex; flex-direction: column; gap: 12px; }
  h1 { font-size: 22px; font-weight: 650; margin: 0 0 4px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 13px; text-align: left; }
  input { font: inherit; padding: 8px 10px; border-radius: 8px; border: 1px solid #444; background: #1c1c1c; color: #f5f5f5; }
  button { font: inherit; font-weight: 700; padding: 10px 18px; border: 0; border-radius: 999px; background: #f5f5f5; color: #141414; cursor: pointer; }
  button.secondary { background: transparent; color: #f5f5f5; border: 1px solid #555; }
  #error { min-height: 1.5em; color: #ffb4b4; font-size: 14px; }
</style>
</head>
<body>
<form id="signin" method="post" action="/management/session">
  <h1>Sign in to CLIProxy</h1>
  <label>User id <input name="user_id" autocomplete="username" required></label>
  <label>Firebase token <input name="firebase_token" autocomplete="off" spellcheck="false" required></label>
  <label>Company name <input name="company_name" autocomplete="organization" value="{{.Company}}" required></label>
  <input type="hidden" name="next" value="{{.Next}}">
  <button type="submit">Continue</button>
  {{if .Google}}<button type="button" class="secondary" id="google">Sign in with Google</button>{{end}}
  <p id="error" role="alert">{{.Error}}</p>
</form>
<script>
var next = {{.Next}};
var allowedHosts = {{.Hosts}};
function show(text) {
  document.getElementById("error").textContent = text || "";
}
function originAllowed(origin) {
  try { return allowedHosts.indexOf(new URL(origin).hostname) !== -1; }
  catch (e) { return false; }
}
function submit(userId, token, company) {
  show("Signing in.");
  fetch("/management/session", {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type": "application/json", "Accept": "application/json"},
    body: JSON.stringify({user_id: userId, firebase_token: token, company_name: company, next: next})
  }).then(function (response) {
    return response.json().catch(function () { return {}; }).then(function (data) {
      if (!response.ok) throw new Error(data.error || "Sign-in failed.");
      location.assign(data.next || next);
    });
  }).catch(function (error) {
    show(error.message || "Sign-in failed.");
  });
}
document.getElementById("signin").addEventListener("submit", function (event) {
  event.preventDefault();
  var form = event.target;
  submit(form.user_id.value.trim(), form.firebase_token.value.trim(), form.company_name.value.trim());
});
window.addEventListener("message", function (event) {
  var data = event.data;
  if (!data || data.type !== "cliproxy:auth" || !originAllowed(event.origin)) return;
  if (!data.userId || !data.firebaseToken || !data.companyName) return;
  submit(String(data.userId), String(data.firebaseToken), String(data.companyName));
});
var params = new URLSearchParams(location.search);
var queryUser = params.get("user_id") || "";
var queryToken = params.get("firebase_token") || "";
var queryCompany = params.get("company_name") || "";
if (queryUser && queryToken && queryCompany) {
  params.delete("user_id");
  params.delete("firebase_token");
  params.delete("company_name");
  history.replaceState(null, "", location.pathname + (params.toString() ? "?" + params.toString() : "") + location.hash);
  submit(queryUser, queryToken, queryCompany);
}
{{if .Google}}
function loadScript(src) {
  return new Promise(function (resolve, reject) {
    var script = document.createElement("script");
    script.src = src;
    script.onload = resolve;
    script.onerror = function () { reject(new Error("Could not load " + src)); };
    document.head.appendChild(script);
  });
}
document.getElementById("google").addEventListener("click", function () {
  var button = document.getElementById("google");
  button.disabled = true;
  loadScript("https://www.gstatic.com/firebasejs/11.6.0/firebase-app-compat.js")
    .then(function () { return loadScript("https://www.gstatic.com/firebasejs/11.6.0/firebase-auth-compat.js"); })
    .then(function () {
      if (!firebase.apps.length) {
        firebase.initializeApp({
          apiKey: {{.APIKey}},
          authDomain: {{.AuthDomain}},
          projectId: {{.ProjectID}}
        });
      }
      return firebase.auth().signInWithPopup(new firebase.auth.GoogleAuthProvider());
    })
    .then(function (result) {
      return result.user.getIdToken().then(function (idToken) {
        var company = document.querySelector('input[name="company_name"]').value.trim();
        submit(result.user.uid, idToken, company);
      });
    })
    .catch(function (error) {
      button.disabled = false;
      var code = error && error.code ? error.code : "";
      var text = (error && error.message) || "Sign-in failed.";
      if (code === "auth/unauthorized-domain") text = "Google sign-in is not available on this address.";
      show(text);
    });
});
{{end}}
</script>
</body>
</html>
`))

package management

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	firebaseCertURL     = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
	firebaseTokenLeeway = 30 * time.Second
	firebaseCertTTL     = time.Hour
)

func firebaseTokenFromRequest(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if token := strings.TrimSpace(c.GetHeader("X-Firebase-Token")); token != "" {
		return token
	}
	authorization := strings.TrimSpace(c.GetHeader("Authorization"))
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return authorization
}

// AuthenticateFirebase accepts a management call when the Firebase ID token is
// valid, the user id is that token's subject, and the company name is this
// server's company. The management key is not consulted.
func (h *Handler) AuthenticateFirebase(clientIP string, localClient bool, userID, company, token string) (bool, int, string) {
	_, ok, status, msg := h.authenticateFirebase(clientIP, localClient, userID, company, token, time.Now())
	return ok, status, msg
}

func (h *Handler) authenticateFirebase(_ string, localClient bool, userID, company, token string, now time.Time) (time.Time, bool, int, string) {
	if h == nil {
		return time.Time{}, false, http.StatusForbidden, "remote management disabled"
	}
	if !localClient && !h.remoteManagementAllowed() {
		return time.Time{}, false, http.StatusForbidden, "remote management disabled"
	}

	userID = strings.TrimSpace(userID)
	company = strings.TrimSpace(company)
	token = strings.TrimSpace(token)
	if userID == "" || company == "" || token == "" {
		return time.Time{}, false, http.StatusUnauthorized, "user id, firebase token, and company name are required"
	}
	if len(userID) > 128 || len(company) > 128 || len(token) > 16384 {
		return time.Time{}, false, http.StatusUnauthorized, "invalid firebase token"
	}

	expected, err := expectedCompanyName()
	if err != nil || expected == "" {
		return time.Time{}, false, http.StatusForbidden, "company is not configured"
	}
	if !strings.EqualFold(company, expected) {
		return time.Time{}, false, http.StatusForbidden, "company name does not match this server"
	}
	projectID := firebaseProjectID()
	if projectID == "" {
		return time.Time{}, false, http.StatusForbidden, "firebase project is not configured"
	}

	sub, expires, err := verifyFirebaseIDToken(token, now, projectID, firebaseCerts.publicKey)
	if err != nil || sub == "" || sub != userID || !expires.After(now) {
		return time.Time{}, false, http.StatusUnauthorized, "invalid firebase token"
	}
	if expires.After(now.Add(time.Hour)) {
		expires = now.Add(time.Hour)
	}
	return expires, true, 0, ""
}

func firebaseProjectID() string {
	return strings.TrimSpace(os.Getenv("FIREBASE_PROJECT_ID"))
}

func expectedCompanyName() (string, error) {
	if name := strings.TrimSpace(os.Getenv("CLIPROXY_COMPANY_NAME")); name != "" {
		return name, nil
	}
	body, err := os.ReadFile("/company_name")
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(body))
	if name == "" {
		return "", errors.New("empty company name")
	}
	return name, nil
}

type firebaseCertCache struct {
	mu      sync.Mutex
	fetched time.Time
	byKID   map[string]*rsa.PublicKey
	fetch   func() (map[string]*rsa.PublicKey, error)
}

var firebaseCerts = &firebaseCertCache{
	fetch: fetchFirebaseCerts,
}

func (c *firebaseCertCache) publicKey(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byKID == nil || time.Since(c.fetched) > firebaseCertTTL {
		if err := c.refresh(); err != nil && c.byKID == nil {
			return nil, err
		}
	}
	if key := c.byKID[kid]; key != nil {
		return key, nil
	}
	if err := c.refresh(); err != nil {
		return nil, err
	}
	key := c.byKID[kid]
	if key == nil {
		return nil, errors.New("unknown signing key")
	}
	return key, nil
}

func (c *firebaseCertCache) refresh() error {
	fetch := c.fetch
	if fetch == nil {
		fetch = fetchFirebaseCerts
	}
	keys, err := fetch()
	if err != nil {
		return err
	}
	c.byKID = keys
	c.fetched = time.Now()
	return nil
}

func fetchFirebaseCerts() (map[string]*rsa.PublicKey, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(firebaseCertURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("firebase cert status %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var encoded map[string]string
	if err := json.Unmarshal(payload, &encoded); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(encoded))
	for kid, pemText := range encoded {
		key, err := rsaPublicKeyFromPEM(pemText)
		if err != nil {
			continue
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("firebase certs missing")
	}
	return keys, nil
}

func rsaPublicKeyFromPEM(pemText string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("pem decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an rsa key")
	}
	return key, nil
}

type firebaseClaims struct {
	Issuer   string          `json:"iss"`
	Audience json.RawMessage `json:"aud"`
	Subject  string          `json:"sub"`
	Expires  float64         `json:"exp"`
	Issued   float64         `json:"iat"`
	AuthTime float64         `json:"auth_time"`
}

func verifyFirebaseIDToken(token string, now time.Time, projectID string, lookup func(string) (*rsa.PublicKey, error)) (string, time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || lookup == nil {
		return "", time.Time{}, errors.New("bad token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", time.Time{}, err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", time.Time{}, err
	}
	if header.Alg != "RS256" || header.Kid == "" || len(header.Kid) > 256 {
		return "", time.Time{}, errors.New("bad header")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, err
	}
	var claims firebaseClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return "", time.Time{}, err
	}
	issuer := "https://securetoken.google.com/" + projectID
	if claims.Issuer != issuer || !audienceMatches(claims.Audience, projectID) {
		return "", time.Time{}, errors.New("bad audience")
	}
	if claims.Subject == "" || len(claims.Subject) > 128 {
		return "", time.Time{}, errors.New("bad subject")
	}
	leeway := firebaseTokenLeeway.Seconds()
	nowSec := float64(now.Unix())
	if claims.Expires < nowSec-leeway || claims.Issued > nowSec+leeway || claims.AuthTime < 0 || claims.AuthTime > nowSec+leeway {
		return "", time.Time{}, errors.New("bad time")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", time.Time{}, err
	}
	publicKey, err := lookup(header.Kid)
	if err != nil {
		return "", time.Time{}, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sum[:], signature); err != nil {
		return "", time.Time{}, err
	}
	return claims.Subject, time.Unix(int64(claims.Expires), 0), nil
}

func audienceMatches(raw json.RawMessage, projectID string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == projectID
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false
	}
	for _, item := range many {
		if item == projectID {
			return true
		}
	}
	return false
}

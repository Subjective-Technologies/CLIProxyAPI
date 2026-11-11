package management

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyFirebaseIDTokenAcceptsSignedToken(t *testing.T) {
	key := testRSAKey(t)
	now := time.Unix(1_700_000_000, 0)
	token := testFirebaseToken(t, key, "kid-1", "test-project", "user-123", now)
	lookup := func(kid string) (*rsa.PublicKey, error) {
		if kid != "kid-1" {
			t.Fatalf("kid %s", kid)
		}
		return &key.PublicKey, nil
	}
	sub, exp, err := verifyFirebaseIDToken(token, now, "test-project", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if sub != "user-123" {
		t.Fatalf("sub %s", sub)
	}
	if !exp.Equal(now.Add(time.Hour)) {
		t.Fatalf("exp %s", exp)
	}
}

func TestVerifyFirebaseIDTokenRejectsWrongProjectAndExpiry(t *testing.T) {
	key := testRSAKey(t)
	now := time.Unix(1_700_000_000, 0)
	token := testFirebaseToken(t, key, "kid-1", "other-project", "user-123", now)
	lookup := func(string) (*rsa.PublicKey, error) { return &key.PublicKey, nil }
	if _, _, err := verifyFirebaseIDToken(token, now, "test-project", lookup); err == nil {
		t.Fatal("expected audience failure")
	}
	expired := testFirebaseToken(t, key, "kid-1", "test-project", "user-123", now.Add(-2*time.Hour))
	if _, _, err := verifyFirebaseIDToken(expired, now, "test-project", lookup); err == nil {
		t.Fatal("expected expiry failure")
	}
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testFirebaseToken(t *testing.T, key *rsa.PrivateKey, kid, project, subject string, now time.Time) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss":       "https://securetoken.google.com/" + project,
		"aud":       project,
		"sub":       subject,
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
	})
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

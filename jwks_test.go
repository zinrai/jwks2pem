package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAJWTVaultSignedVerifiesWithOneOfThePEMs(t *testing.T) {
	keys, err := signingKeys(readFixture(t, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := slotFiles(keys, len(keys))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(readFixture(t, "vault-token.jwt")))
	for _, f := range files {
		if verifiesRS256(t, f, token) {
			return
		}
	}
	t.Fatal("no PEM verifies the token Vault signed")
}

func TestAnECKeyComesOutAsTheSamePublicKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := priv.Public().(*ecdsa.PublicKey)
	point, _ := pub.Bytes()
	set := jwksOf(map[string]string{"kty": "EC", "use": "sig", "kid": "ec", "crv": "P-256",
		"x": b64url(point[1:33]), "y": b64url(point[33:])})
	keys, err := signingKeys(set)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(parsePEM(t, pemOf(keys[0]))) {
		t.Fatal("PEM holds a different public key")
	}
}

func TestEncryptionAndUnusableKeysAreSkippedAndTooManyIsAnError(t *testing.T) {
	sig, _ := rsa.GenerateKey(rand.Reader, 2048)
	enc, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	set := jwksOf(rsaJWK("sig", "sig", &sig.PublicKey), rsaJWK("enc", "enc", &enc.PublicKey),
		map[string]string{"kty": "OKP", "use": "sig", "kid": "ed", "crv": "Ed25519", "x": b64url(edPub)})
	keys, err := signingKeys(set)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].kid != "sig" {
		t.Fatalf("kept %d keys, want only the RSA signing key", len(keys))
	}
	keys = append(keys, keys[0])
	if _, err := slotFiles(keys, 1); err == nil {
		t.Fatal("2 keys fit in 1 slot")
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func verifiesRS256(t *testing.T, pemBytes []byte, token string) bool {
	t.Helper()
	pub, ok := parsePEM(t, pemBytes).(*rsa.PublicKey)
	if !ok {
		return false
	}
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
}

func parsePEM(t *testing.T, pemBytes []byte) any {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func pemOf(k signingKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: k.der})
}

func rsaJWK(kid, use string, pub *rsa.PublicKey) map[string]string {
	return map[string]string{"kty": "RSA", "use": use, "kid": kid,
		"n": b64url(pub.N.Bytes()), "e": b64url([]byte{1, 0, 1})}
}

func jwksOf(keys ...map[string]string) []byte {
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

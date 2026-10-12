package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type signingKey struct {
	kid string
	der []byte
}

func fetch(url, cacert string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	if cacert != "" {
		pemBytes, err := os.ReadFile(cacert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("%s: no certificate", cacert)
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// Signing keys only, not every key: a JWKS may also hold encryption keys
// (use "enc"), which no JWT signature verifies against. Key types a PEM
// verifier commonly cannot use are skipped, not refused, so that one such
// key does not block the rest.
func signingKeys(body []byte) ([]signingKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	if set.Keys == nil {
		return nil, errors.New(`no "keys" member: not a JWKS`)
	}
	var keys []signingKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := publicKey(k)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k.Kid, err)
		}
		if pub == nil {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k.Kid, err)
		}
		keys = append(keys, signingKey{kid: k.Kid, der: der})
	}
	if len(keys) == 0 {
		return nil, errors.New("no RSA or EC signing key")
	}
	// By kid, not in the JWKS's order, which a provider need not keep: the
	// same keys then land in the same files, and nothing is rewritten.
	slices.SortFunc(keys, func(a, b signingKey) int { return strings.Compare(a.kid, b.kid) })
	return keys, nil
}

var curves = map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}

// nil, not an error, for a key a PEM verifier commonly cannot use.
func publicKey(k jwk) (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		curve, ok := curves[k.Crv]
		if !ok {
			return nil, nil
		}
		return ecKey(curve, k)
	}
	return nil, nil
}

func ecKey(curve elliptic.Curve, k jwk) (*ecdsa.PublicKey, error) {
	x, err := b64(k.X)
	if err != nil {
		return nil, err
	}
	y, err := b64(k.Y)
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size {
		return nil, errors.New("coordinate longer than the curve")
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1+size-len(x):1+size], x)
	copy(point[1+2*size-len(y):], y)
	return ecdsa.ParseUncompressedPublicKey(curve, point)
}

func b64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("missing key member")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// Exactly slots files, not one per key: a verifier configured with a fixed
// list of N paths needs N readable keys. Slots beyond the keys repeat the
// first key, which is deterministic, unlike a throwaway key that would
// change every run.
func slotFiles(keys []signingKey, slots int) ([][]byte, error) {
	if len(keys) > slots {
		return nil, fmt.Errorf("%d signing keys, more than %d slots", len(keys), slots)
	}
	files := make([][]byte, slots)
	for i := range files {
		k := keys[0]
		if i < len(keys) {
			k = keys[i]
		}
		files[i] = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: k.der})
	}
	return files, nil
}

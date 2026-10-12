// Package join implements join tokens and the join handshake that brings a
// new device into the mesh.
//
// A token carries a random secret plus the addresses and certificate
// fingerprints of the server nodes that can accept it. The join API uses a
// self-signed certificate pinned by that fingerprint, so no CA or domain is
// needed and a man in the middle cannot impersonate the mesh.
package join

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const tokenPrefix = "mg1."

// Server is one place a token can be redeemed.
type Server struct {
	Addr string `json:"a"`  // host:port of the join API
	FP   string `json:"fp"` // hex sha256 of the server certificate
}

// Token is the decoded form of a join token string.
type Token struct {
	ID      string   `json:"id"`
	Secret  string   `json:"s"`
	Servers []Server `json:"srv"`
}

// Encode renders the token as a copy-pasteable string.
func (t Token) Encode() string {
	b, _ := json.Marshal(t)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// Decode parses a token string.
func Decode(s string) (Token, error) {
	var t Token
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, tokenPrefix) {
		return t, fmt.Errorf("not a meshgate token")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, tokenPrefix))
	if err != nil {
		return t, fmt.Errorf("token: %w", err)
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return t, fmt.Errorf("token: %w", err)
	}
	if t.ID == "" || t.Secret == "" || len(t.Servers) == 0 {
		return t, fmt.Errorf("token is incomplete")
	}
	return t, nil
}

// NewSecret returns a random secret and its stored hash.
func NewSecret() (secret, hash string) {
	b := make([]byte, 24)
	rand.Read(b)
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, HashSecret(secret)
}

// HashSecret hashes a secret for storage.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// CheckSecret compares a secret with a stored hash in constant time.
func CheckSecret(secret, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(hash)) == 1
}

// RandomID returns a short random hex ID.
func RandomID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// InstallURL is the installer used in generated commands.
const InstallURL = "https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh"

// InstallURLWindows is the PowerShell installer.
const InstallURLWindows = "https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.ps1"

// InstallCommands returns copy-paste commands that install meshgate and join
// with token: a Linux shell, pfSense's Command Prompt and an elevated
// Windows PowerShell.
func InstallCommands(token string) (linux, pfsense, windows string) {
	linux = "curl -fsSL " + InstallURL + " | sudo sh -s -- join " + token
	pfsense = "fetch -qo - " + InstallURL + " | sh -s -- join " + token
	windows = "& ([scriptblock]::Create((irm " + InstallURLWindows + "))) join " + token
	return
}

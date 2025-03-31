package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// HS256 Algorithm to build a JWT.
func HS256(header, payload, secret string) (string, error) {
	h := hmac.New(sha256.New, []byte(secret))

	// Create a new HMAC-SHA256 hash
	_, e1 := h.Write([]byte(header + "." + payload))
	if e1 != nil {
		return "", e1
	}

	// Get the resulting hash as a byte slice
	signature := h.Sum(nil)

	// Convert the hash to a hexadecimal string
	encSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encSignature, nil
}

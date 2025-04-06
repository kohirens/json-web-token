package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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

// RS256 Algorithm PKCS1 to build a JWT.
func RS256(header, payload, privateKeyPem string) (string, error) {
	// Data to be signed
	// Hash the message using SHA256
	hashed := sha256.Sum256([]byte(header + "." + payload))

	// PKCS#1 RSAPrivateKey
	block, _ := pem.Decode([]byte(privateKeyPem))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if privateKey == nil {
		return "", errors.New("invalid private key")
	}

	// Sign the hashed message
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		panic(err)
	}

	// Convert the hash to a hexadecimal string
	encSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encSignature, nil
}

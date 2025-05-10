package jwt

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// HS256 Algorithm to build a JWT.
func HS256(header, payload string, secret []byte) (string, error) {
	h := hmac.New(sha256.New, secret)

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
func RS256(header, payload string, privateKeyPem []byte) (string, error) {
	// Hash the data message to be signed using SHA256
	hashed := sha256.Sum256([]byte(header + "." + payload))
	privateKey, e1 := loadPrivateKey(privateKeyPem)
	if e1 != nil {
		return "", e1
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

// ValidateRS256 validate the RSASSA-PKCS1-v1_5 SHA-256 digital signature
// contained in the JWS Signature by using the public key to decrypt the
// signature and verify that it matches the hash of the combined header and
// payload.
func ValidateRS256(publicKeyPem []byte, encSignature, encHeaderPlusPayload []byte) error {
	signature := make([]byte, base64.RawURLEncoding.DecodedLen(len(encSignature)))

	_, e1 := base64.RawURLEncoding.Decode(signature, encSignature)
	if e1 != nil {
		return fmt.Errorf(stderr.Base64Decode, e1.Error())
	}

	// Hash the message using SHA256
	hashed := sha256.Sum256(encHeaderPlusPayload)

	publicKey, e2 := loadPublicKey(publicKeyPem)
	if e2 != nil {
		return e2
	}

	if e := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); e != nil {
		return fmt.Errorf(stderr.InvalidSignature, e.Error())
	}

	return nil
}

func ValidateSignatureRS256Pub(token []byte, key *rsa.PublicKey) error {
	parts := bytes.Split(token, []byte("."))
	encSignature := parts[2]
	encHeaderPlusPayload := bytes.Join([][]byte{parts[0], parts[1]}, []byte("."))

	signature := make([]byte, base64.RawURLEncoding.DecodedLen(len(encSignature)))
	_, e1 := base64.RawURLEncoding.Decode(signature, encSignature)
	if e1 != nil {
		return fmt.Errorf(stderr.Base64Decode, e1.Error())
	}

	// Hash the message using SHA256
	hashed := sha256.Sum256(encHeaderPlusPayload)

	if e := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature); e != nil {
		return fmt.Errorf(stderr.InvalidSignature, e.Error())
	}

	return nil
}

// loadPublicKey Load a PKCS#1 or PKCS#8 public key in PEM format. No other
// format has been tested.
// Go isn't designed so that you can pass different types from a function without
// the using magic. However, the drawback is that  usfunction is nearly identical to the loadPrivateKey function because Go
// make it nearly impossible to return mores 1 type from a function. A drawback
// of strongly typed languages is duplication.
func loadPublicKey(publicKeyPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		return nil, fmt.Errorf(stderr.DecodePublicKey)
	}

	var publicKey *rsa.PublicKey
	var err error

	switch block.Type {
	case "RSA PUBLIC KEY": // PKCS#1
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY": // PKCS#8
		var pk interface{}
		pk, err = x509.ParsePKIXPublicKey(block.Bytes)
		publicKey = pk.(*rsa.PublicKey)
	default:
		return nil, fmt.Errorf(stderr.UnknownKeyFmt, block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf(stderr.PublicKey, err.Error())
	}

	return publicKey, nil
}

// loadPrivateKey Load a PKCS#1 or PKCS#8 private key in PEM format. No other
// format has been tested.
func loadPrivateKey(privateKeyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPem)
	if block == nil {
		return nil, fmt.Errorf(stderr.DecodePublicKey)
	}

	var err error
	var privateKey *rsa.PrivateKey

	switch block.Type {
	case "RSA PRIVATE KEY": // PKCS#1
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY": // PKCS#8
		var pk interface{}
		pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		privateKey = pk.(*rsa.PrivateKey)
	default:
		return nil, fmt.Errorf(stderr.UnknownKeyFmt, block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf(stderr.PrivateKey, err.Error())
	}

	return privateKey, nil
}

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JsonMap Represents an object that can be converted to the JSON that a JWT requires.
type JsonMap map[string]interface{}

// Header Represents the claim fields to put into a JWT header.
// The keys that are required here are up to the service provider. So be sure
// to read their documentation for JWT requirements first.
type Header JsonMap

// Payload Represents the claim fields to put into a JWT payload.
// The keys that are required here are up to the service provider, although
// there are some that are standard. So be sure to read their documentation for
// JWT requirements first.
type Payload JsonMap

// FormatTime Use to convert a time suitable for "exp", "iat", and "nbf" in the expected format. Will convert to UTC, then format.
func FormatTime(t time.Time) string {
	return fmt.Sprintf("%v", t.UTC().Unix())
}

// Token Generate a JWT token from the Header, Payload, and secret as specified
// by the JWT specification.
func Token(header JsonMap, payload JsonMap, secret string) (string, error) {
	encHeader, e1 := Encode(header)
	if e1 != nil {
		return "", e1
	}

	encPayload, e2 := Encode(payload)
	if e2 != nil {
		return "", e2
	}

	// Now that we have the header and payload as base64 strings, we can encode
	// them into a JWT token and return that.
	sig, e3 := HS256(encHeader, encPayload, secret)
	if e3 != nil {
		return "", e3
	}

	return encHeader + "." + encPayload + "." + sig, nil
}

// Encode Will convert the JsonMap into a JSON string.
// Then encode the JSON string into a base64 string as JWT requires and return
// that.
func Encode(content JsonMap) (string, error) {
	data, e1 := json.Marshal(content)
	if e1 != nil {
		return "", fmt.Errorf(Stderr.CannotEncodeJSON, e1.Error())
	}

	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "="), nil
}

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Info struct {
	Algorithm        string
	Compact          bool
	EncodedHeader    string
	EncodedPayload   string
	EncodedSignature string
	Header           ClaimSet
	Payload          ClaimSet
	Token            string
	Type             string
	Valid            bool
}

// ClaimSet Represents an object that can be converted to the JSON that a JWT requires.
type ClaimSet map[string]interface{}

const (
	jwsCompact = 2
	jweCompact = 4
	cAlg       = "alg"
	algHS256   = "HS256"
	algRS256   = "RS256"
	sep        = "."
)

// FormatTime Use to convert a time suitable for "exp", "iat", and "nbf" in the expected format. Will convert to UTC, then format.
func FormatTime(t time.Time) int64 {
	return t.UTC().Unix()
}

// Token Generate a JWT token from the header, payload, and secret as specified
// by the JWT specification.
//
//	Note that ambiguities can arise due to differing platform representations
//	of line breaks (CRLF versus LF), differing spacing at the beginning
//	and ends of lines, whether the last line has a terminating line break
//	or not, and other causes. However, with the ClaimSet type
//	there are no line-breaks, space, nor tabs present in the JSON output
//	before base64 encoding.
func Token(header ClaimSet, payload ClaimSet, secret string) (string, error) {
	encHeader, e1 := Encode(header)
	if e1 != nil {
		return "", e1
	}

	encPayload, e2 := Encode(payload)
	if e2 != nil {
		return "", e2
	}

	var encSig string
	var e3 error

	// Using the header and payload encoded as base64 strings, we can now build
	// a signature encoded using the desired Algorithm.
	alg, ok := header[cAlg].(string)
	if !ok {
		return "", errors.New(stderr.AlgNotInHeader)
	}
	switch alg {
	case algHS256:
		encSig, e3 = HS256(encHeader, encPayload, secret)
	case algRS256:
		encSig, e3 = RS256(encHeader, encPayload, secret)
	}

	if e3 != nil {
		return "", e3
	}

	// Put it all base64 pieces together as a JWT token and return.
	return encHeader + sep + encPayload + sep + encSig, nil
}

// Encode Will convert the ClaimSet into a JSON string.
// Then encode the JSON string into a base64 string as JWT requires and return
// that.
func Encode(content ClaimSet) (string, error) {
	data, e1 := json.Marshal(content)
	if e1 != nil {
		return "", fmt.Errorf(stderr.CannotEncodeJSON, e1.Error())
	}

	// TODO: Verify the padding should be removed here.
	//return strings.TrimRight(base64.RawURLEncoding.EncodeToString(data), "="), nil
	return base64.RawURLEncoding.EncodeToString(data), nil
}

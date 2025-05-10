package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

var whitespaceReg = regexp.MustCompile("([\n\r\t ]+)")

// Validate A JWT according to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-7.2).
//
//	This function provides convenience when working with bytes.
func Validate(token, secret []byte, requiredPayloadClaims []string) (*Info, error) {
	return ValidateString(string(token), string(secret), requiredPayloadClaims)
}

// ValidateString A JWT according to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-7.2).
//  1. Verify that the JWT contains at least one period ('.') character.
//  2. Let the Encoded JOSE Header be the portion of the JWT before the first
//     period ('.') character.
//  3. Base64url decode the Encoded JOSE Header following the
//     restriction that no line breaks, whitespace, or other additional
//     characters have been used.
//  4. Verify that the resulting octet sequence is a UTF-8-encoded
//     representation of a completely valid JSON object conforming to
//     RFC 7159 [RFC7159]; let the JOSE Header be this JSON object.
func ValidateString(token, secret string, requiredPayloadClaims []string) (*Info, error) {
	if whitespaceReg.MatchString(token) {
		return nil, &ErrInvalidFmt{"whitespace characters detected in the token"}
	}

	info, e1 := Parse(token)
	if e1 != nil {
		return nil, e1
	}

	// A bit of extra validation to ensure the keys that are required per
	// vendor are there.
	for _, claim := range requiredPayloadClaims { // this search is not case-insensitive.
		_, ok := info.Payload[claim]
		if !ok {
			return nil, &ErrMissingClaim{claim}
		}
	}

	switch info.Algorithm {
	case algRS256:
		if e := ValidateRS256([]byte(secret), []byte(info.EncodedSignature), []byte(info.EncodedHeader+"."+info.EncodedPayload)); e != nil {
			return nil, e
		}
	}

	info.Valid = true
	return info, nil
}

func decodeClaims(data string) (ClaimSet, error) {
	var ret ClaimSet
	h, e1 := base64.RawURLEncoding.DecodeString(data)

	if e1 != nil {
		return nil, fmt.Errorf(stderr.Base64Decode)
	}

	if e := json.Unmarshal(h, &ret); e != nil {
		return nil, e
	}

	return ret, nil
}

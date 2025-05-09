package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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

	info, e1 := parse(token)
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
		if e := ValidateRS256([]byte(secret), info.EncodedSignature, info.EncodedHeader+"."+info.EncodedPayload); e != nil {
			return nil, e
		}
	}

	return info, nil
}

func decodeClaims(data string) (JsonMap, error) {
	var ret JsonMap
	h, e1 := base64.RawURLEncoding.DecodeString(data)

	if e1 != nil {
		return nil, fmt.Errorf(stderr.Base64Decode)
	}

	if e := json.Unmarshal(h, &ret); e != nil {
		return nil, e
	}

	return ret, nil
}

// Validate Run checks on the JOSE header according to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-7.2)
func validHeader(encodedHeader string) error {
	// 3. Base64url decode the Encoded JOSE Header following the restriction
	// that no line breaks, whitespace, or other additional characters have
	// been used.

	h, e1 := decodeClaims(encodedHeader)
	if e1 != nil {
		return &ErrInvalidFmt{"header " + e1.Error()}
	}
	algFound := false
	// contains the `alg` claim
	for claim, _ := range h {
		if strings.ToLower(claim) == "alg" {
			algFound = true
			break
		}
	}
	if !algFound {
		return fmt.Errorf(stderr.AlgNotInHeader)
	}

	return nil
}

// parse Determines the type of JWT to understand how best to validate it
// according to
// [RFC7516 Section 9](https://www.rfc-editor.org/rfc/rfc7516.html#section-9).
func parse(token string) (*Info, error) {
	numSeparators := strings.Count(token, ".")
	if numSeparators < 1 {
		return nil, &ErrInvalidFmt{}
	}

	parts := strings.Split(token, ".")

	header, e1 := decodeClaims(parts[0])
	if e1 != nil {
		return nil, &ErrInvalidFmt{"header " + e1.Error()}
	}

	alg, ok := lookUp(header, "alg") // do a case-insensitive lookup here.
	if !ok {
		return nil, fmt.Errorf(stderr.AlgNotInHeader)
	}

	if e := validHeader(parts[0]); e != nil {
		return nil, &ErrInvalidFmt{"invalid header " + e.Error()}
	}

	payload, e2 := decodeClaims(parts[1])
	if e2 != nil {
		return nil, &ErrInvalidFmt{"payload " + e2.Error()}
	}

	//	If the object is using the JWS Compact Serialization or the JWE
	//	Compact Serialization, the number of base64url-encoded segments
	//	separated by period ('.') characters differs for JWSs and JWEs.
	//	JWSs have three segments separated by two period ('.') characters.
	//	JWEs have five segments separated by four period ('.') characters.
	if numSeparators == jwsCompact { // assume JWS compact serialization
		return &Info{
			Algorithm:        alg,
			EncodedHeader:    parts[0],
			EncodedPayload:   parts[1],
			EncodedSignature: parts[2],
			Compact:          true,
			Type:             "JWS",
			Header:           header,
			Payload:          payload,
		}, nil
	}

	// If the object is using the JWS JSON Serialization or the JWE JSON
	// Serialization, the members used will be different. JWSs have a
	// "payload" member and JWEs do not. JWEs have a "ciphertext" member
	// and JWSs do not. However, there is no way to determine if these are
	// present without decoding the whole thing, thus the only reliable way is
	// to count the number of separators, and assume the type.
	// See more JWS examples in [Appendix A. JWS Examples](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A)
	if numSeparators == jweCompact { // assume JWS compact serialization
		return &Info{
			Algorithm: alg,
			Compact:   true,
			Type:      "JWE",
		}, nil
	}

	return nil, fmt.Errorf(stderr.ParseToken)
}

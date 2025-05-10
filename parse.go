package jwt

import (
	"fmt"
	"strings"
)

// Parse Determines the JWT type according to
// [RFC7516 Section 9](https://www.rfc-editor.org/rfc/rfc7516.html#section-9)
// and returns Info for use in a program.
func Parse(token string) (*Info, error) {
	numSeparators := strings.Count(token, ".")
	if numSeparators < 1 {
		return nil, &ErrInvalidFmt{}
	}

	parts := strings.Split(token, ".")

	//	If the object is using the JWS Compact Serialization or the JWE
	//	Compact Serialization, the number of base64url-encoded segments
	//	separated by period ('.') characters differs for JWSs and JWEs.
	//	JWSs have three segments separated by two period ('.') characters.
	//	JWEs have five segments separated by four period ('.') characters.
	if numSeparators == jwsCompact { // assume JWS compact serialization
		return ParseJWS(parts)
	}

	// If the object is using the JWS JSON Serialization or the JWE JSON
	// Serialization, the members used will be different. JWSs have a
	// "payload" member and JWEs do not. JWEs have a "ciphertext" member
	// and JWSs do not. However, there is no way to determine if these are
	// present without decoding the whole thing, thus the only reliable way is
	// to count the number of separators, and assume the type.
	// See more JWS examples in [Appendix A. JWS Examples](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A)
	if numSeparators == jweCompact { // assume JWS compact serialization
		return ParseJWE(parts)
	}

	return nil, fmt.Errorf(stderr.ParseToken)
}

// ParseJWS Parse and return the JWT as a JWS and return Info to use.
func ParseJWS(parts []string) (*Info, error) {
	header, e1 := decodeClaims(parts[0])
	if e1 != nil {
		return nil, &ErrInvalidFmt{"header " + e1.Error()}
	}

	alg, ok := lookUp(header, "alg") // do a case-insensitive lookup here.
	if !ok {
		return nil, fmt.Errorf(stderr.AlgNotInHeader)
	}

	payload, e2 := decodeClaims(parts[1])
	if e2 != nil {
		return nil, &ErrInvalidFmt{"payload " + e2.Error()}
	}

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

// ParseJWE Parse and return the JWT as a JWE and return Info to use.
func ParseJWE(parts []string) (*Info, error) {
	header, e1 := decodeClaims(parts[0])
	if e1 != nil {
		return nil, &ErrInvalidFmt{"header " + e1.Error()}
	}

	// TODO: Parse a JWE

	return &Info{
		EncodedHeader: parts[0],
		Compact:       true,
		Type:          "JWE",
		Header:        header,
	}, nil
}

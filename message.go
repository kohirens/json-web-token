package jwt

var stderr = struct {
	AlgNotInHeader,
	Base64Decode,
	CannotEncodeJSON,
	DecodePublicKey,
	InvalidSignature,
	MissingSeparator,
	ParseToken,
	PrivateKey,
	PublicKey,
	SigMismatch,
	UnknownKeyFmt string
}{
	AlgNotInHeader:   "alg not found in header",
	Base64Decode:     "failed base64 standard decoding",
	CannotEncodeJSON: "could not encode data to json: %v",
	DecodePublicKey:  "failed to decode public key",
	InvalidSignature: "invalid signature: %v",
	MissingSeparator: "invalid token, missing separator \".\"",
	ParseToken:       "could not parse token",
	PrivateKey:       "invalid private key: %v",
	PublicKey:        "invalid public key: %v",
	SigMismatch:      "the signature does not match, check that you are using the correct public key",
	UnknownKeyFmt:    "unknown key format 5v",
}

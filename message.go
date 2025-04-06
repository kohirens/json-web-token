package jwt

var stderr = struct {
	AlgNotInHeader,
	CannotEncodeJSON string
}{
	AlgNotInHeader:   "alg not found in header",
	CannotEncodeJSON: "could not encode data to json: %v",
}

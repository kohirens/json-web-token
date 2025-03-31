package jwt

var Stderr = struct {
	CannotEncodeJSON string
}{
	CannotEncodeJSON: "could not encode data to json: %v",
}

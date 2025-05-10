package jwt

import (
	"fmt"
	"net/http"
	"strings"
)

func ExampleToken() {
	header := ClaimSet{
		"alg": "RS256",
	}
	payload := ClaimSet{
		"admin": true,
		"iat":   1516239022,
		"name":  "John Doe",
		"sub":   "1234567890",
	}

	tkn, _ := Token(header, payload, load("jwtRS256.key"))

	req, e1 := http.NewRequest("GET", "http://example.com/", nil)
	if e1 != nil {
		fmt.Println(e1.Error())
		return
	}

	req.Header.Add("Authorization", "Bearer "+tkn)

	// Output:
}

func ExampleValidateRS256() {
	header := ClaimSet{
		"alg": "RS256",
	}
	payload := ClaimSet{
		"admin": true,
		"iat":   1516239022,
		"name":  "John Doe",
		"sub":   "1234567890",
	}

	// Build a JWT using an RSA private key in PEM format.
	token, _ := Token(header, payload, load("jwtRS256.key"))

	// Setup for validation.
	publicKeyPem := load("jwtRS256.key.pub")

	// If you already know the algorithm, you can skip the detection.
	parts := strings.Split(token, ".")
	signature := []byte(parts[2])
	headerAndPayload := []byte(parts[0] + "." + parts[1])
	if e := ValidateRS256(publicKeyPem, signature, headerAndPayload); e != nil {
		fmt.Println(e)
		return
	}

	fmt.Println("token is valid")
	// Output: token is valid
}

func ExampleValidate() {
	header := ClaimSet{
		"alg": "RS256",
	}
	payload := ClaimSet{
		"admin": true,
		"iat":   1516239022,
		"name":  "John Doe",
		"sub":   "1234567890",
	}

	// Build a JWT using an RSA private key in PEM format.
	token, _ := Token(header, payload, load("jwtRS256.key"))

	// Setup for validation.
	publicKeyPem := load("jwtRS256.key.pub")

	// Validate a Token, normally you would call Validate, which auto-detects
	// how to validate a token based on the header.
	info, e1 := Validate([]byte(token), publicKeyPem, []string{"iat", "sub"})
	if e1 != nil {
		fmt.Println(e1.Error())
		return
	}

	fmt.Printf("the token is a valid %v token\n", info.Type)
	// Output: the token is a valid JWS token
}

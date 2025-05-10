package jwt

import (
	"fmt"
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
	fmt.Printf("token: %v\n", tkn)
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

	// Build a JWT using a RSA private key in PEM format.
	token, _ := Token(header, payload, load("jwtRS256.key"))

	// Setup for validation.
	parts := strings.Split(token, ".")
	publicKeyPem := load("jwtRS256.key.pub")
	signature := []byte(parts[2])
	headerAndPayload := []byte(parts[0] + "," + parts[1])

	// Validate a Token, normally you would call Validate, which auto-detects
	// how to validate a token based on the header.
	info, e1 := Validate([]byte(token), publicKeyPem, []string{"iat", "sub"})
	if e1 != nil {
		fmt.Println(e1.Error())
		return
	}

	// Output: the token is a valid JWS token
	fmt.Printf("the token is a valid %v token\n", info.Type)

	if e := ValidateRS256(publicKeyPem, signature, headerAndPayload); e != nil {
		fmt.Println(e)
		return
	}

	// Output: token is valid
	fmt.Println("token is valid")
}

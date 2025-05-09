package jwt

import (
	"fmt"
	"strings"
)

func ExampleToken() {
	header := JsonMap{
		"alg": "RS256",
	}
	payload := JsonMap{
		"admin": true,
		"iat":   1516239022,
		"name":  "John Doe",
		"sub":   "1234567890",
	}
	tkn, _ := Token(header, payload, string(load("jwtRS256.key")))
	fmt.Printf("token: %v\n", tkn)
}

func ExampleValidateRS256() {
	header := JsonMap{
		"alg": "RS256",
	}
	payload := JsonMap{
		"admin": true,
		"iat":   1516239022,
		"name":  "John Doe",
		"sub":   "1234567890",
	}
	token, _ := Token(header, payload, string(load("jwtRS256.key")))
	parts := strings.Split(token, ".")
	publicKeyPem := load("jwtRS256.key.pub")
	signature := parts[2]
	headerAndPayload := parts[0] + "," + parts[1]

	if e := ValidateRS256(publicKeyPem, signature, headerAndPayload); e != nil {
		fmt.Println(e)
		return
	}

	// Output: token is valid
	fmt.Println("token is valid")
}

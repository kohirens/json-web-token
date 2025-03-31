# JSON Web Token

A library to build JSON Web Tokens.

This library does not contain a lot of magic. Making it very clean and simple.
Because of that, you can build almost any JWT without needing the author to
update the library.

## Examples:

```go
// Build a JWT for Tableau Cloud
package main

import (
	"github.com/google/uuid"
	"github.com/kohirens/cloud/tableau"
	"github.com/kohirens/json-web-token/jwt"
)

func main() {
	header := jwt.JsonMap{
		"kid": "connectedAppSecretId",
		"iss": "connectedAppClientId",
		"alg": "HS256",
		"typ": "JWT",
	}
	payload := jwt.JsonMap{
		"aud": "tableau",
		"exp": jwt.FormatTime(time.Now().Add(9 * time.Minute).UTC()),
		"sub": "user@example.com",
		"jti": uuid.NewString(),
		"scp": []string{"tableau:views:embed", "tableau:metrics:embed"},
	}

	token, e1 := jwt.Token(header, payload, "connectedAppSecretKey")
	if e1 != nil {
		panic(e1.Error())
	}

	tableau.NewServer(&http.Client{}, token)
}

```
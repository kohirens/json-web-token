# JSON Web Token

A library to build JSON Web Tokens.

This library does not contain a lot of magic. Making it very clean and simple.
Because of that, you can build almost any JWT without needing the author to
update the library.

For more info see  [resources] and [anatomy].

## Examples:

### Build a JWT from Scratch

```go
package main

import (
	"github.com/google/uuid"
	"github.com/kohirens/cloud/tableau"
	"github.com/kohirens/json-web-token/jwt"
)

func main() {
	header := jwt.ClaimSet{
		"kid": "connectedAppSecretId",
		"iss": "connectedAppClientId",
		"alg": "HS256",
		"typ": "JWT",
	}
	payload := jwt.ClaimSet{
		"aud": "tableau",
		"exp": jwt.FormatTime(time.Now().Add(9 * time.Minute).UTC()),
		"sub": "user@example.com",
		"jti": uuid.NewString(),
		"scp": []string{"tableau:views:embed", "tableau:metrics:embed"},
	}

	token, e1 := jwt.BuildJWS(header, payload, "appSecretOrKey")
	if e1 != nil {
		panic(e1.Error())
	}

	tableau.NewServer(&http.Client{}, token)
}

```

### GitHub JWT:

```go
// Build a JWT for GitHub
package main

import (
	"github.com/kohirens/json-web-token/jwt"
	"github.com/kohirens/stdlib/logger"
	"os"
)

var (
	log = logger.Standard{}
)

func main() {
	clientId := "aaaaaaaaa"
	privatePemKey, e1 := os.ReadFile("rsa-priavate-pkcs1-key.pem")
	if e1 != nil {
		log.Errf(e1.Error())
		os.Exit(1)
    }

	token, e1 := jwt.GitHub(clientId, privatePemKey)
	if e1 != nil {
		log.Errf(e1.Error())
		os.Exit(1)
	}
	
	// Do something with the token like pass it to a GitHub Client.
	_ = token
}

```

---

[anatomy]: /docs/anatomy.md
[resources]: /docs/resources.md

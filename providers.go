package jwt

import "time"
import "github.com/google/uuid"

// Tableau Build a JWT for Tableau Cloud.
func Tableau(userEmail, connectedAppClientId, connectedAppSecretId, connectedAppSecretKey string) (string, error) {
	header := JsonMap{
		"kid": connectedAppSecretId,
		"iss": connectedAppClientId,
		"alg": "HS256",
		"typ": "JWT",
	}
	payload := JsonMap{
		"aud": "tableau",
		"exp": FormatTime(time.Now().Add(9 * time.Minute)),
		"sub": userEmail,
		"jti": uuid.NewString(),
		"scp": []string{"tableau:views:embed", "tableau:metrics:embed"},
	}

	ss, e1 := Token(header, payload, connectedAppSecretKey)
	if e1 != nil {
		panic(e1.Error())
	}

	return ss, nil
}

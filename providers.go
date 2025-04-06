package jwt

import (
	"github.com/google/uuid"
	"time"
)

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
		return "", e1
	}

	return ss, nil
}

// GitHub Build a JWT for an Application.
// For details see
// https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
func GitHub(clientId, privateKeyPem string) (string, error) {
	header := JsonMap{
		"alg": "RS256",
		"typ": "JWT",
	}
	payload := JsonMap{
		"iat": FormatTime(time.Now().Add(-time.Duration(60) * time.Second)),
		"exp": FormatTime(time.Now().Add(9 * time.Minute)),
		"iss": clientId,
	}

	ss, e1 := Token(header, payload, privateKeyPem)
	if e1 != nil {
		return "", e1
	}

	return ss, nil
}

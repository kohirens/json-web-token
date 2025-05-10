package jwt

import (
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name           string
		header         ClaimSet
		payload        ClaimSet
		secret         []byte
		validateSecret []byte
		required       []string
		want           bool
		wantErr        bool
	}{
		{
			"valid",
			ClaimSet{
				"alg": "RS256",
			},
			ClaimSet{
				"iss":            "https://accounts.google.com",
				"azp":            "1234987819200.apps.googleusercontent.com",
				"aud":            "1234987819200.apps.googleusercontent.com",
				"sub":            "10769150350006150715113082367",
				"at_hash":        "HK6E_P6Dh8Y93mRNtsDB1Q",
				"hd":             "example.com",
				"email":          "jsmith@example.com",
				"email_verified": "true",
				"iat":            1353601026,
				"exp":            1353604926,
				"nonce":          "0394852-3190485-2490358",
			},
			load("jwtRS256.key"),
			load("jwtRS256.key.pub"),
			[]string{"aud", "exp", "iat", "iss", "sub"},
			true,
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			token, _ := Token(c.header, c.payload, c.secret)

			got, err := Validate([]byte(token), c.validateSecret, c.required)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidateString() error = %v, wantErr %v", err, c.wantErr)
				return
			}

			if got.Valid != c.want {
				t.Errorf("ValidateString() got = %v, want %v", got, c.want)
			}
		})
	}
}

func TestValid(t *testing.T) {
	cases := []struct {
		name      string
		token     []byte
		secret    []byte
		required  []string
		want      ClaimSet
		wantErr   bool
		wantType  string
		wantValid bool
	}{
		{
			"valid-RS256-jws",
			load("rs256-valid-token.txt"),
			load("jwtRS256.key.pub"),
			[]string{"iat", "sub"},
			ClaimSet{
				"sub":   "1234567890",
				"name":  "John Doe",
				"admin": true,
				"iat":   1516239022,
			},
			false,
			"JWS",
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			info, err := Validate(c.token, c.secret, c.required)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidateString() error = %v, wantErr %v", err, c.wantErr)
				return
			}

			if info != nil && info.Type != c.wantType && info.Valid != c.wantValid {
				t.Errorf("ValidateString() got = %v, want %v", info.Type, c.wantType)
				return
			}
		})
	}
}

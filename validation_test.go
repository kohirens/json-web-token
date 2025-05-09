package jwt

import (
	"os"
	"reflect"
	"testing"
)

/*
	{
	  "iss": "https://accounts.google.com",
	  "azp": "1234987819200.apps.googleusercontent.com",
	  "aud": "1234987819200.apps.googleusercontent.com",
	  "sub": "10769150350006150715113082367",
	  "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",
	  "hd": "example.com",
	  "email": "jsmith@example.com",
	  "email_verified": "true",
	  "iat": 1353601026,
	  "exp": 1353604926,
	  "nonce": "0394852-3190485-2490358"
	}
*/
func TestValidate(t *testing.T) {
	cases := []struct {
		name     string
		header   JsonMap
		payload  JsonMap
		secret   string
		required []string
		want     JsonMap
		wantErr  bool
	}{
		{
			"valid",
			JsonMap{},
			JsonMap{
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
			"",
			[]string{"aud", "exp", "iat", "iss", "sub"},
			JsonMap{},
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			token, _ := Token(c.header, c.payload, c.secret)

			got, err := ValidateString(token, c.secret, c.required)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidateString() error = %v, wantErr %v", err, c.wantErr)
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ValidateString() got = %v, want %v", got, c.want)
			}
		})
	}
}

func TestValid(t *testing.T) {
	cases := []struct {
		name     string
		token    []byte
		secret   []byte
		required []string
		want     JsonMap
		wantErr  bool
	}{
		{
			"valid-RS256-jws",
			load("rs256-valid-token.txt"),
			load("jwtRS256.key.pub"),
			[]string{"iat", "sub"},
			JsonMap{
				"sub":   "1234567890",
				"name":  "John Doe",
				"admin": true,
				"iat":   1516239022,
			},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			
			_, err := Validate(c.token, c.secret, c.required)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidateString() error = %v, wantErr %v", err, c.wantErr)
				return
			}
		})
	}
}

func load(filename string) []byte {
	data, e1 := os.ReadFile(fixturesDir + "/" + filename)
	if e1 != nil {
		panic(e1)
	}
	return data
}

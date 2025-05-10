package jwt

import (
	"testing"
)

func TestVerifyRS256(t *testing.T) {
	type args struct {
		publicKeyPem         string
		encSignature         string
		encHeaderPlusPayload string
	}
	cases := []struct {
		name          string
		header        ClaimSet
		payload       ClaimSet
		privateKeyPem []byte
		publicKeyPem  []byte
		wantErr       bool
	}{
		{
			"valid",
			ClaimSet{"alg": "RS256"},
			ClaimSet{"iss": "https://auth.example.com/"},
			load("jwtRS256.key"),
			load("jwtRS256.key.pub"),
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tkn, e1 := Token(c.header, c.payload, c.privateKeyPem)
			if (e1 != nil) != c.wantErr {
				t.Errorf("TestVerifyRS256() error = %v, wantErr %v", e1, c.wantErr)
				return
			}

			token, e2 := Parse(tkn)
			if (e2 != nil) != c.wantErr {
				t.Errorf("TestVerifyRS256() error = %v, wantErr %v", e2, c.wantErr)
				return
			}
			if err := ValidateRS256(c.publicKeyPem, []byte(token.EncodedSignature), []byte(token.EncodedHeader+"."+token.EncodedPayload)); (err != nil) != c.wantErr {
				t.Errorf("VerifyRS256() error = %v, wantErr %v", err, c.wantErr)
				return
			}
		})
	}
}

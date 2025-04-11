package jwt

import (
	"os"
	"strings"
	"testing"
)

func TestGitHub(t *testing.T) {
	cases := []struct {
		name     string
		clientId string
		pemFile  string
		want     string
		wantErr  bool
	}{
		{"invalid", "abcdefgahi", "private-key-pkcs8-pem.txt", "", true},
		{"valid", "abcdefgahi", "private-key-pkcs1-pem.txt", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiO", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, _ := os.ReadFile("testdata/" + c.pemFile)
			got, err := GitHub(c.clientId, string(key))

			if (err != nil) != c.wantErr {
				t.Errorf("GitHub() error = %v, wantErr %v", err, c.wantErr)
				return
			}

			if !strings.Contains(got, c.want) {
				t.Errorf("GitHub() got = %v, want %v", got, c.want)
				return
			}
		})
	}
}

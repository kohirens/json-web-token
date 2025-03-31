package jwt

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type MockJWT struct {
	Header  JsonMap `json:"header"`
	Payload JsonMap `json:"payload"`
}

func TestToken(runner *testing.T) {
	cases := []struct {
		name    string
		secret  string
		want    string
		wantErr bool
	}{
		{
			"success",
			"1234",
			"eyJhbGciOiJIUzI1NiIsImlzcyI6IjQzMjEiLCJraWQiOiIxMjM0In0.eyJhdWQiOiJ0YWJsZWF1IiwiZXhwIjoiIiwianRpIjoidXVpZC5yYW5kb20iLCJzY3AiOlsidGFibGVhdTp2aWV3OmVtYmVkIl0sInN1YiI6Im1lQGV4YW1wbGUuY29tIn0",
			false,
		},
	}

	for _, c := range cases {
		runner.Run(c.name, func(t *testing.T) {
			data, _ := os.ReadFile("testdata/example-jwt.json")
			fixture := &MockJWT{}
			_ = json.Unmarshal(data, fixture)

			got, gotErr := Token(fixture.Header, fixture.Payload, c.secret)
			if gotErr != nil && !c.wantErr {
				t.Errorf("Token() gotErr %v", gotErr)
				return
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("Token() = %v, did not contain %v", got, c.want)
				return
			}
		})
	}
}

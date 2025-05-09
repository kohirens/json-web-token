package jwt

import "strings"

// lookUp Case insensitive search for a key in a JsonMap, returning the value
// and boolean indicating if it has been found.
func lookUp(d JsonMap, key string) (string, bool) {
	for k, v := range d {
		if strings.ToLower(k) == strings.ToLower(key) {
			return v.(string), true
		}
	}
	return "", false
}

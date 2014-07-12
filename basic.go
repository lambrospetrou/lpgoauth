package lpgoauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// BasicRealm is used when setting the WWW-Authenticate response header.
var BasicRealm = "Authorization Required"

type ValidCredFunc func(string, string) bool

// SecureCompare performs a constant time compare of two strings
// to limit timing attacks. This means that regardless of the character
// that differs from the two given strings the time it will take is the same
func SecureCompare(sa string, sb string) bool {
	saSha := sha256.Sum256([]byte(sa))
	sbSha := sha256.Sum256([]byte(sb))

	return subtle.ConstantTimeCompare(saSha[:], sbSha[:]) == 1
}

// Returns a handler that firstly checks for Basic authorization and if it succeeds it
// delegates the call to the handler you provide. So an easy way to wrap
// your existing handlers in order to provide Basic Authentication.
// The function to be provided as first argument takes the username and password
// as specified in the 'Authorization' header and should return True if valid
// or False otherise.
func BasicAuthHandler(fnValid ValidCredFunc,
	fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authenticate the authorization
		auth := r.Header.Get("Authorization")
		if len(auth) < 6 || auth[:6] != "Basic " {
			rejectAuthBasic(w)
			return
		}
		b, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			rejectAuthBasic(w)
			return
		}
		tokens := strings.SplitN(string(b), ":", 2)
		if len(tokens) != 2 || !fnValid(tokens[0], tokens[1]) {
			rejectAuthBasic(w)
			return
		}

		// delegate the call if credentials are valid
		fn(w, r)
	}
}

// reject the request and inform the sender about the Basic Authorization requirement
// THIS WILL DISPLAY THE CREDENTIALS BOX IN THE BROWSERS
func rejectAuthBasic(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+BasicRealm+"\"")
	http.Error(w, "Not Authorized", http.StatusUnauthorized)
}

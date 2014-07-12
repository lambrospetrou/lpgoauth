LP Go Authorization library
===========================

# Inspiration
The library here is inspired by the implementation of the Martini framework but without the requirement for their own Martini context object. This way we can use Basic Authorization with existing handlers without problems.

# Usage

    package main

    import (
        "github.com/lambrospetrou/lpgoauth"
	    "net/http"
	    "fmt"
    )

    // check the credentials given - this is a function provided by you to the handler
    func isBasicCredValid(user string, pass string) bool {
        if lpgoauth.SecureCompare(user, "test_user") {
            return lpgoauth.SecureCompare(pass, "test_pass")
	    }
	    return false
    }

    func testHandler(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w,"Secured user!")
    }

    func main() {
        http.HandleFunc("/securedEndpoint", lpgoauth.BasicAuthHandler(isBasicCredValid, testHandler))
	    http.ListenAndServe(":8080", nil)
    }


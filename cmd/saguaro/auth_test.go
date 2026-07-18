package main

import (
	"strings"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	phc, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$") {
		t.Fatalf("unexpected PHC prefix: %s", phc)
	}
	if !verifyPassword("correct horse battery staple", phc) {
		t.Fatal("correct password rejected")
	}
	if verifyPassword("wrong password", phc) {
		t.Fatal("wrong password accepted")
	}
}

func TestPasswordHashUniqueSalt(t *testing.T) {
	a, _ := hashPassword("same-password-here")
	b, _ := hashPassword("same-password-here")
	if a == b {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	cases := []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=65536,t=1,p=4$YWJj$YWJj",   // wrong variant
		"$argon2id$v=18$m=65536,t=1,p=4$YWJj$YWJj",  // wrong version
		"$argon2id$v=19$m=65536,t=1,p=4$!!$YWJj",    // bad salt encoding
		"$argon2id$v=19$m=65536,t=1,p=4$YWJj$",      // empty key
		"$argon2id$v=19$m=banana,t=1,p=4$YWJj$YWJj", // bad params
	}
	for _, c := range cases {
		if verifyPassword("anything", c) {
			t.Fatalf("malformed hash accepted: %q", c)
		}
	}
}

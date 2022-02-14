package argon2_test

import (
	"testing"

	"github.com/marlonmp/argon2"
)

func Test_Encode(t *testing.T) {
	password := "&Bad_Pa$Sword_123&"

	hash := argon2.GenerateHash(password)

	isEqual, _ := argon2.VerifyHash(password, hash)

	if !isEqual {
		t.Fail()
	}
}

package argon2

import "crypto/rand"

/*

	getRandomSalt: Gets the salt length and returns a random salt

*/
func getRandomSalt(len uint8) []byte {
	salt := make([]byte, len)

	rand.Read(salt)

	return salt
}

/*

	validateSalt: Gets a salt in []byte and returns true if this is valid

*/
func validateSalt(salt []byte) bool {
	return len(salt) >= 8
}

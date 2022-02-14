package argon2

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Possible errors in hash verifications

var (
	AlgorithmNotSupported = errors.New("argon2: algorithm not supported")
	InvalidSalt           = errors.New("argon2: invalid salt")
	InvalidHash           = errors.New("argon2: invalid hash")
	InvalidHashParameters = errors.New("argon2: invalid hash parameters")
)

// const hashFormat = "$%s$v=%d$m=%d,t=%d,p=%d$%s$%s"

/*

	getEncoded: Gets salt and password hashed in base64, and argon2 options.
	Returns a hash in string like this:

	"$argon2id$v=19$m=16,t=2,p=2$TZgerOg7WKyBpypUzqDiOw$Fm4/Egbr/0WJ/XK5VVAqWQ"

*/
func getEncoded(base64Salt, base64Hash []byte, options *Options) string {

	versionStr := strconv.Itoa(options.Version)
	memoryStr := strconv.Itoa(int(options.Memory))
	iterationsStr := strconv.Itoa(int(options.Iterations))
	parallelismStr := strconv.Itoa(int(options.Parallelism))

	buffLen := len(versionStr) + len(memoryStr) + len(iterationsStr) + len(parallelismStr) + len(base64Salt) + len(base64Hash) + 16

	buff := make([]byte, buffLen)

	buffer := bytes.NewBuffer(buff)

	buffer.WriteByte('$')
	buffer.WriteString(options.Algorithm.GetAlgorithm())

	buffer.WriteString("$v=")
	buffer.WriteString(versionStr)

	buffer.WriteString("$m=")
	buffer.WriteString(memoryStr)
	buffer.WriteByte(',')

	buffer.WriteString("t=")
	buffer.WriteString(iterationsStr)
	buffer.WriteByte(',')

	buffer.WriteString("p=")
	buffer.WriteString(parallelismStr)

	buffer.WriteByte('$')
	buffer.Write(base64Salt)

	buffer.WriteByte('$')
	buffer.Write(base64Hash)

	return buffer.String()
}

/*

	GenerateHash: Gets a password with optional hash options and returns the password hashed in argon2 with a random salt.

*/
func GenerateHash(password string, customOptions ...Options) string {

	options := validateOptions(customOptions)

	salt := getRandomSalt(options.SaltLength)

	return generateHash([]byte(password), salt, options)
}

/*

	GenerateHashNSalt: Gets password and salt in string and optional options and return the password hashed in argon2.

	Return the error InvalidSalt if the salt is invalid

*/
func GenerateHashNSalt(password, salt string, customOptions ...Options) (string, error) {
	options := validateOptions(customOptions)

	saltBytes := []byte(salt)

	if !validateSalt(saltBytes) {
		return "", InvalidSalt
	}

	return generateHash([]byte(password), saltBytes, options), nil
}

/*

	generateHash: Gets password and salt in []byte and hash options and returns the hash in argon2.

*/
func generateHash(password, salt []byte, options *Options) string {

	passwordHashed := options.Algorithm.Hash(salt, password, options)

	enc := base64.RawStdEncoding

	base64Salt := make([]byte, enc.EncodedLen(len(salt)))
	base64Password := make([]byte, enc.EncodedLen(len(passwordHashed)))

	enc.Encode(base64Salt, salt)
	enc.Encode(base64Password, passwordHashed)

	return getEncoded(base64Salt, base64Password, options)
}

/*

	splitHash: Gets a encoded Hash in string and return the parameters hash in *string.

	Return the InvalidHsh error if the hash is not valid

*/
func splitHash(encodedHash *string) (alg, version, memory, iterations, parallelism, base64Salt, base64Password string, err error) {

	err = InvalidHash

	args := strings.Split(*encodedHash, `$`)

	if len(args) != 6 {
		return
	}

	params := strings.Split(args[3], `,`)

	if len(params) != 3 {
		return
	}

	err = nil

	alg = args[1]
	version = args[2][2:]
	memory = params[0][2:]
	iterations = params[1][2:]
	parallelism = params[2][2:]

	base64Salt = args[4]
	base64Password = args[5]

	return
}

/*

	VerifyHash: Gets password and encodedHash in string and compare if the password is equal to the encoded hash.

	Return the InvalidHash error if the hash is not valid, or return a error from base64.RawStdEncoding.Strict().DecodeString.

*/
func VerifyHash(password, encodedHash string) (bool, error) {

	alg, version, memory, iterations, parallelism, base64Salt, base64PasswordHashed, err := splitHash(&encodedHash)

	if err != nil {
		return false, err
	}

	saltBytes, err := base64.RawStdEncoding.Strict().DecodeString(base64Salt)

	if err != nil {
		return false, err
	}

	passwordHashedBytes, err := base64.RawStdEncoding.Strict().DecodeString(base64PasswordHashed)

	if err != nil {
		return false, err
	}

	options, err := strToOptions(&alg, &version, &memory, &iterations, &parallelism, len(passwordHashedBytes))

	if err != nil {
		return false, err
	}

	passwordBytes := []byte(password)

	passwordHashed := options.Algorithm.Hash(saltBytes, passwordBytes, options)

	return subtle.ConstantTimeCompare(passwordHashedBytes, passwordHashed) == 1, nil
}

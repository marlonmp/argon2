package argon2

import (
	"strconv"

	"golang.org/x/crypto/argon2"
)

type Options struct {

	// Argon2 information
	Algorithm   algorithm
	Version     int
	Memory      uint32
	Iterations  uint32
	Parallelism uint8

	// Hash information
	HashLength uint32
	SaltLength uint8
}

var defaultOptions = &Options{
	Algorithm:   &Argon2ID{},
	Version:     argon2.Version,
	Memory:      64,
	Iterations:  3,
	Parallelism: 3,

	HashLength: 32,
	SaltLength: 16,
}

/*

	validateOptions: Gets an Options array then validate all its parameters and finally returns a valid Options.

*/
func validateOptions(customOptions []Options) *Options {

	if len(customOptions) == 0 {
		return defaultOptions
	}

	options := &customOptions[0]

	if options == nil {
		return defaultOptions
	}

	if options.Algorithm == nil {
		options.Algorithm = &Argon2ID{}
	}

	options.Version = argon2.Version

	if options.Memory < 16 {
		options.Memory = 16
	}

	if options.Iterations < 1 {
		options.Iterations = 1
	}

	if options.Parallelism < 1 {
		options.Parallelism = 1
	}

	if options.HashLength < 4 {
		options.HashLength = 4
	}

	if options.SaltLength < 8 {
		options.SaltLength = 8
	}

	return options
}

/*

	strToOptions: Gets all Options parameters in *string and validates it.

	Return a InvalidHash error if one parameter is invalid.

*/
func strToOptions(alg, version, memory, iterations, parallelism *string, hashLen int) (*Options, error) {

	errs := make([]error, 5)

	var i64 int

	options := new(Options)

	options.Algorithm, errs[0] = getAlgorithm(*alg)

	options.Version, errs[1] = strconv.Atoi(*version)

	i64, errs[2] = strconv.Atoi(*memory)
	options.Memory = uint32(i64)

	i64, errs[3] = strconv.Atoi(*iterations)
	options.Iterations = uint32(i64)

	i64, errs[4] = strconv.Atoi(*parallelism)
	options.Parallelism = uint8(i64)

	options.HashLength = uint32(hashLen)

	for _, err := range errs {
		if err != nil {
			return nil, InvalidHash
		}
	}

	return options, nil
}

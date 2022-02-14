package argon2

import "golang.org/x/crypto/argon2"

// algorithms
const (
	// D  = "argon2d"
	I  = "argon2i"
	ID = "argon2id"
)

// get Algorithm

func getAlgorithm(alg string) (algorithm, error) {
	switch alg {
	case I:
		return &Argon2I{}, nil

	// case D:
	// 	return &argon2D{}, nil

	case ID:
		return &Argon2ID{}, nil

	default:
		return nil, AlgorithmNotSupported
	}
}

type algorithm interface {
	// Returns the algorithm
	GetAlgorithm() string

	// Hash the password according the algorithm
	Hash(salt, password []byte, options *Options) []byte
}

// Argon2D

type argon2D struct{}

func (Ad *argon2D) GetAlgorithm() string {
	return "argon2d"
}

func (Ad *argon2D) Hash(salt, password []byte, options *Options) []byte {

	return []byte{}
}

// Argon2I

type Argon2I struct{}

func (Ai *Argon2I) GetAlgorithm() string {
	return "argon2i"
}

func (Ai *Argon2I) Hash(salt, password []byte, options *Options) []byte {

	return argon2.Key(password, salt, options.Iterations, options.Memory*1024, options.Parallelism, options.HashLength)
}

// Argon2ID

type Argon2ID struct{}

func (Aid *Argon2ID) GetAlgorithm() string {
	return "argon2id"
}

func (Aid *Argon2ID) Hash(salt, password []byte, options *Options) []byte {

	return argon2.IDKey(password, salt, options.Iterations, options.Memory*1024, options.Parallelism, options.HashLength)
}

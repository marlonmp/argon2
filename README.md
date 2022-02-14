# Argon2

This package add functionality to [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2), for generating argon2 hashes and verify it.

## Installation

```bash
$ go get github.com/marlonmp/argon2
```

## Usage

### Generate Hash

If you want to generate hash with default options, only set a password, GenerateHash function create a randoms salt.

```golang
password := "some password"

hash := argon2.GenerateHash(password)
```

If you want to generate your own salt, no biggie, you can pass it in GenerateHashNSalt function.

```golang
salt := "some salt"

password := "&Bad_Pa$Sword_123&"

hash, err := argon2.GenerateHashNSalt(password, salt)

if err == argon2.InvalidSalt { ... }
```

Or if you want to create your custom options, check this out.

```golang

// default options in argon2
var defaultOptions = &Options{
	Algorithm:   &Argon2ID{},
	Version:     argon2.Version,
	Memory:      64,
	Iterations:  3,
	Parallelism: 3,

	HashLength: 32,
	SaltLength: 16,
}

// You can create your custom options, and modify whatever you want.

myOptions := &argon2.Options{
	Algorithm:   &argon2.Argon2I{},
	Iterations:  4,
}

password := "some password"

hash := argon2.GenerateHash(password, myOptions)

```

### Verification

To verify if the password is equal to a encoded hash, call the VerifyHash function.
```golang
password := "some password"
encodedHash := "some encoded hash"


isEqual, err := argon2.VerifyHash(password, encodedHash)

if err == argon2.InvalidHash { ... }

if err == argon2.InvalidSalt { ... }

// base64 error
if err != nil { ... }

if isEqual {
    println(password, "is equal to:", encodedHash)

} else {
    println(password, "is not equal to:", encodedHash)

}
```
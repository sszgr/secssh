package crypto

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

type KDFParams struct {
	Salt        []byte `json:"salt"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"key_len"`
}

func DefaultKDFParams(kdf string) (KDFParams, error) {
	switch kdf {
	case "argon2id":
		return KDFParams{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, KeyLen: 32}, nil
	case "pbkdf2-sha256":
		return KDFParams{Iterations: 600000, KeyLen: 32}, nil
	default:
		return KDFParams{}, errors.New("unsupported kdf")
	}
}

func DeriveKey(password []byte, kdf string, p KDFParams) ([]byte, error) {
	if len(p.Salt) == 0 {
		return nil, errors.New("kdf salt is required")
	}
	if p.KeyLen == 0 {
		p.KeyLen = 32
	}
	switch kdf {
	case "argon2id":
		if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 {
			return nil, errors.New("invalid argon2id params")
		}
		key := argon2.IDKey(password, p.Salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
		return key, nil
	case "pbkdf2-sha256":
		if p.Iterations == 0 {
			return nil, errors.New("invalid pbkdf2 iterations")
		}
		key := pbkdf2.Key(password, p.Salt, int(p.Iterations), int(p.KeyLen), sha256.New)
		return key, nil
	default:
		return nil, errors.New("unsupported kdf")
	}
}

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func NonceSize(cipherName string) (int, error) {
	switch cipherName {
	case "aes-256-gcm":
		return 12, nil
	case "xchacha20-poly1305":
		return chacha20poly1305.NonceSizeX, nil
	default:
		return 0, errors.New("unsupported cipher")
	}
}

func Encrypt(cipherName string, key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := buildAEAD(cipherName, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce length")
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func Decrypt(cipherName string, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := buildAEAD(cipherName, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce length")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func buildAEAD(cipherName string, key []byte) (cipher.AEAD, error) {
	switch cipherName {
	case "aes-256-gcm":
		if len(key) != 32 {
			return nil, errors.New("aes-256-gcm requires 32-byte key")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "xchacha20-poly1305":
		if len(key) != chacha20poly1305.KeySize {
			return nil, errors.New("xchacha20-poly1305 requires 32-byte key")
		}
		return chacha20poly1305.NewX(key)
	default:
		return nil, errors.New("unsupported cipher")
	}
}

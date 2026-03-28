package crypto

var (
	supportedKDF = map[string]struct{}{
		"argon2id":      {},
		"pbkdf2-sha256": {},
	}
	supportedCipher = map[string]struct{}{
		"aes-256-gcm":        {},
		"xchacha20-poly1305": {},
	}
)

func SupportedKDFNames() []string {
	return []string{"argon2id", "pbkdf2-sha256"}
}

func SupportedCipherNames() []string {
	return []string{"aes-256-gcm", "xchacha20-poly1305"}
}

func IsSupportedKDF(name string) bool {
	_, ok := supportedKDF[name]
	return ok
}

func IsSupportedCipher(name string) bool {
	_, ok := supportedCipher[name]
	return ok
}

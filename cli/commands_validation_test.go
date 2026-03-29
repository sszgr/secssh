package cli

import "testing"

func TestRunUnknownCommand(t *testing.T) {
	code := Run([]string{"nope"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestCmdCryptoSetValidation(t *testing.T) {
	ref := vaultRef{Path: "/tmp/not-used"}

	if code := cmdCrypto([]string{"set"}, ref); code != 2 {
		t.Fatalf("expected usage error for missing flags, got %d", code)
	}
	if code := cmdCrypto([]string{"set", "--kdf", "bad", "--cipher", "aes-256-gcm"}, ref); code != 2 {
		t.Fatalf("expected usage error for bad kdf, got %d", code)
	}
	if code := cmdCrypto([]string{"set", "--kdf", "argon2id", "--cipher", "bad"}, ref); code != 2 {
		t.Fatalf("expected usage error for bad cipher, got %d", code)
	}
}

func TestCmdHostAuthSetValidation(t *testing.T) {
	ref := vaultRef{Path: "/tmp/not-used"}

	if code := cmdHost([]string{"auth", "set", "prod", "--mode", "bad"}, ref); code != 2 {
		t.Fatalf("expected invalid mode usage error, got %d", code)
	}
	if code := cmdHost([]string{"auth", "set", "prod", "--mode", "password", "--password-policy", "stored"}, ref); code != 2 {
		t.Fatalf("expected missing password-ref usage error, got %d", code)
	}
	if code := cmdHost([]string{"auth", "set", "prod", "--mode", "key", "--password-policy", "bad"}, ref); code != 2 {
		t.Fatalf("expected invalid password-policy usage error, got %d", code)
	}
}

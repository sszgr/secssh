package cli

import "testing"

func TestRunUnknownCommand(t *testing.T) {
	code := Run([]string{"nope"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestCmdCryptoSetValidation(t *testing.T) {
	vaultPath := "/tmp/not-used"

	if code := cmdCrypto([]string{"set"}, vaultPath); code != 2 {
		t.Fatalf("expected usage error for missing flags, got %d", code)
	}
	if code := cmdCrypto([]string{"set", "--kdf", "bad", "--cipher", "aes-256-gcm"}, vaultPath); code != 2 {
		t.Fatalf("expected usage error for bad kdf, got %d", code)
	}
	if code := cmdCrypto([]string{"set", "--kdf", "argon2id", "--cipher", "bad"}, vaultPath); code != 2 {
		t.Fatalf("expected usage error for bad cipher, got %d", code)
	}
}

func TestCmdHostAuthSetValidation(t *testing.T) {
	vaultPath := "/tmp/not-used"

	if code := cmdHost([]string{"auth", "set", "prod", "--mode", "bad"}, vaultPath); code != 2 {
		t.Fatalf("expected invalid mode usage error, got %d", code)
	}
	if code := cmdHost([]string{"auth", "set", "prod", "--mode", "password", "--password-policy", "stored"}, vaultPath); code != 2 {
		t.Fatalf("expected missing password-ref usage error, got %d", code)
	}
	if code := cmdHost([]string{"auth", "set", "prod", "--mode", "key", "--password-policy", "bad"}, vaultPath); code != 2 {
		t.Fatalf("expected invalid password-policy usage error, got %d", code)
	}
}

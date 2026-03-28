package host

import "fmt"

type AuthMode string

const (
	ModeKey      AuthMode = "key"
	ModePassword AuthMode = "password"
	ModeAuto     AuthMode = "auto"
	ModeAsk      AuthMode = "ask"
)

type PasswordPolicy string

const (
	PasswordStored  PasswordPolicy = "stored"
	PasswordPrompt  PasswordPolicy = "prompt"
	PasswordSession PasswordPolicy = "session"
)

func ParseAuthMode(v string) (AuthMode, error) {
	switch AuthMode(v) {
	case ModeKey, ModePassword, ModeAuto, ModeAsk:
		return AuthMode(v), nil
	default:
		return "", fmt.Errorf("invalid --mode: %s", v)
	}
}

func ParsePasswordPolicy(v string) (PasswordPolicy, error) {
	switch PasswordPolicy(v) {
	case PasswordStored, PasswordPrompt, PasswordSession:
		return PasswordPolicy(v), nil
	default:
		return "", fmt.Errorf("invalid --password-policy: %s", v)
	}
}

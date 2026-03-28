package runner

import "github.com/sszgr/secssh/vault"

type Options struct {
	Target     string
	AuthMode   string
	Prompt     bool
	UseSecret  string
	PassArgs   []string
	Vault      *vault.Payload
	VaultPath  string
	SessionExp int64
}

package workspace

import (
	"sync"
	"time"
)

type vaultPasswordEntry struct {
	password  []byte
	expiresAt time.Time
}

var (
	vaultPassMu sync.Mutex
	vaultPassDB = map[string]vaultPasswordEntry{}
)

func PutVaultPassword(path string, password []byte, expiresAt time.Time) {
	vaultPassMu.Lock()
	defer vaultPassMu.Unlock()
	cp := make([]byte, len(password))
	copy(cp, password)
	vaultPassDB[path] = vaultPasswordEntry{password: cp, expiresAt: expiresAt}
}

func GetVaultPassword(path string, now time.Time) ([]byte, bool) {
	vaultPassMu.Lock()
	defer vaultPassMu.Unlock()
	v, ok := vaultPassDB[path]
	if !ok {
		return nil, false
	}
	if !v.expiresAt.IsZero() && !v.expiresAt.After(now) {
		delete(vaultPassDB, path)
		return nil, false
	}
	cp := make([]byte, len(v.password))
	copy(cp, v.password)
	return cp, true
}

func ClearVaultPasswords() {
	vaultPassMu.Lock()
	defer vaultPassMu.Unlock()
	clear(vaultPassDB)
}

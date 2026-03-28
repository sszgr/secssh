package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Status struct {
	Unlocked     bool
	TTLRemaining time.Duration
	VaultPath    string
}

type SessionManager struct {
	vaultPath   string
	defaultTTL  time.Duration
	sessionFile string
}

func NewSessionManager(vaultPath string, defaultTTL time.Duration) *SessionManager {
	return &SessionManager{
		vaultPath:   vaultPath,
		defaultTTL:  defaultTTL,
		sessionFile: sessionPath(),
	}
}

func (m *SessionManager) Unlock() error {
	return m.writeSession(time.Now().Add(m.defaultTTL))
}

func (m *SessionManager) Lock() error {
	if err := os.Remove(m.sessionFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m *SessionManager) ExpiresAt() (time.Time, error) {
	return m.readSession()
}

func (m *SessionManager) Status() (Status, error) {
	exp, err := m.readSession()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Status{Unlocked: false, VaultPath: m.vaultPath}, nil
		}
		return Status{}, err
	}
	remaining := time.Until(exp)
	if remaining <= 0 {
		_ = os.Remove(m.sessionFile)
		return Status{Unlocked: false, VaultPath: m.vaultPath}, nil
	}
	return Status{Unlocked: true, TTLRemaining: remaining, VaultPath: m.vaultPath}, nil
}

func (m *SessionManager) RequireUnlocked() error {
	st, err := m.Status()
	if err != nil {
		return err
	}
	if !st.Unlocked {
		return errors.New("vault is locked, run secssh unlock first")
	}
	return nil
}

func (m *SessionManager) writeSession(exp time.Time) error {
	if err := os.MkdirAll(filepath.Dir(m.sessionFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(m.sessionFile, []byte(strconv.FormatInt(exp.Unix(), 10)), 0o600)
}

func (m *SessionManager) readSession() (time.Time, error) {
	raw, err := os.ReadFile(m.sessionFile)
	if err != nil {
		return time.Time{}, err
	}
	u, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(u, 0), nil
}

func sessionPath() string {
	return filepath.Join(os.TempDir(), "secssh", "session")
}

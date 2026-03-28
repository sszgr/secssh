package vault

import "github.com/sszgr/secssh/crypto"

const (
	FileMagic   = "SECSSH1\n"
	FileVersion = 1
)

type FileHeader struct {
	Version    int              `json:"version"`
	KDFType    string           `json:"kdf_type"`
	KDFParams  crypto.KDFParams `json:"kdf_params"`
	CipherType string           `json:"cipher_type"`
	Nonce      []byte           `json:"nonce"`
}

type Payload struct {
	SSHConfig   string                    `json:"ssh_config"`
	Keys        map[string][]byte         `json:"keys"`
	KeyPublics  map[string]string         `json:"key_publics"`
	Secrets     map[string]string         `json:"secrets"`
	Hosts       map[string]HostAuth       `json:"hosts"`
	Machines    map[string]HostMachine    `json:"machines"`
	Connections map[string]HostConnection `json:"connections"`
	Metadata    map[string]string         `json:"metadata"`
}

type HostAuth struct {
	Mode           string `json:"mode"`
	PasswordPolicy string `json:"password_policy"`
	PasswordRef    string `json:"password_ref,omitempty"`
}

type HostConnection struct {
	ConnectCount    int    `json:"connect_count"`
	LastConnectedAt string `json:"last_connected_at,omitempty"`
	LastAuthMode    string `json:"last_auth_mode,omitempty"`
}

type HostMachine struct {
	HostName string `json:"host_name"`
	User     string `json:"user,omitempty"`
	Port     int    `json:"port,omitempty"`
	KeyRef   string `json:"key_ref,omitempty"`
}

func NewEmptyPayload() *Payload {
	return &Payload{
		Keys:        map[string][]byte{},
		KeyPublics:  map[string]string{},
		Secrets:     map[string]string{},
		Hosts:       map[string]HostAuth{},
		Machines:    map[string]HostMachine{},
		Connections: map[string]HostConnection{},
		Metadata:    map[string]string{},
	}
}

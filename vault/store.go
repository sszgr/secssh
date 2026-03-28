package vault

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sszgr/secssh/crypto"
)

type SaveOptions struct {
	KDFType    string
	CipherType string
	KDFParams  *crypto.KDFParams
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func Initialize(path string, password []byte) error {
	if Exists(path) {
		return errors.New("vault already exists")
	}
	return Save(path, password, NewEmptyPayload(), SaveOptions{
		KDFType:    "argon2id",
		CipherType: "aes-256-gcm",
	})
}

func Load(path string, password []byte) (*FileHeader, *Payload, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	header, ciphertext, err := parseFile(raw)
	if err != nil {
		return nil, nil, err
	}

	key, err := crypto.DeriveKey(password, header.KDFType, header.KDFParams)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := crypto.Decrypt(header.CipherType, key, header.Nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, errors.New("invalid password or corrupted vault")
	}

	payload := NewEmptyPayload()
	if err := json.Unmarshal(plaintext, payload); err != nil {
		return nil, nil, err
	}
	if payload.Keys == nil {
		payload.Keys = map[string][]byte{}
	}
	if payload.KeyPublics == nil {
		payload.KeyPublics = map[string]string{}
	}
	if payload.Secrets == nil {
		payload.Secrets = map[string]string{}
	}
	if payload.Hosts == nil {
		payload.Hosts = map[string]HostAuth{}
	}
	if payload.Machines == nil {
		payload.Machines = map[string]HostMachine{}
	}
	if payload.Connections == nil {
		payload.Connections = map[string]HostConnection{}
	}
	if payload.Metadata == nil {
		payload.Metadata = map[string]string{}
	}
	return header, payload, nil
}

func LoadHeader(path string) (*FileHeader, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	header, _, err := parseFile(raw)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func Save(path string, password []byte, payload *Payload, opts SaveOptions) error {
	if payload == nil {
		return errors.New("payload is nil")
	}
	if opts.KDFType == "" {
		opts.KDFType = "argon2id"
	}
	if opts.CipherType == "" {
		opts.CipherType = "aes-256-gcm"
	}
	if !crypto.IsSupportedKDF(opts.KDFType) {
		return errors.New("unsupported kdf")
	}
	if !crypto.IsSupportedCipher(opts.CipherType) {
		return errors.New("unsupported cipher")
	}

	params := crypto.KDFParams{}
	if opts.KDFParams != nil {
		params = *opts.KDFParams
	} else {
		defaultParams, err := crypto.DefaultKDFParams(opts.KDFType)
		if err != nil {
			return err
		}
		params = defaultParams
	}

	if params.KeyLen == 0 {
		params.KeyLen = 32
	}
	params.Salt = make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, params.Salt); err != nil {
		return err
	}

	nonceLen, err := crypto.NonceSize(opts.CipherType)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	key, err := crypto.DeriveKey(password, opts.KDFType, params)
	if err != nil {
		return err
	}
	ciphertext, err := crypto.Encrypt(opts.CipherType, key, nonce, plaintext, nil)
	if err != nil {
		return err
	}

	header := FileHeader{
		Version:    FileVersion,
		KDFType:    opts.KDFType,
		KDFParams:  params,
		CipherType: opts.CipherType,
		Nonce:      nonce,
	}
	raw, err := packFile(&header, ciphertext)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicWrite(path, raw, 0o600)
}

func ChangePassword(path string, oldPassword, newPassword []byte) error {
	header, payload, err := Load(path, oldPassword)
	if err != nil {
		return err
	}
	params := header.KDFParams
	return Save(path, newPassword, payload, SaveOptions{
		KDFType:    header.KDFType,
		CipherType: header.CipherType,
		KDFParams:  &params,
	})
}

func ChangeCrypto(path string, password []byte, kdf, cipher string) error {
	header, payload, err := Load(path, password)
	if err != nil {
		return err
	}
	params, err := crypto.DefaultKDFParams(kdf)
	if err != nil {
		return err
	}
	// Keep existing key length for compatibility if it is set.
	if header.KDFParams.KeyLen != 0 {
		params.KeyLen = header.KDFParams.KeyLen
	}
	return Save(path, password, payload, SaveOptions{
		KDFType:    kdf,
		CipherType: cipher,
		KDFParams:  &params,
	})
}

func parseFile(raw []byte) (*FileHeader, []byte, error) {
	if len(raw) < len(FileMagic)+4 {
		return nil, nil, errors.New("vault file too small")
	}
	if string(raw[:len(FileMagic)]) != FileMagic {
		return nil, nil, errors.New("invalid vault magic")
	}
	hlen := binary.BigEndian.Uint32(raw[len(FileMagic) : len(FileMagic)+4])
	if int(hlen) <= 0 || len(raw) < len(FileMagic)+4+int(hlen) {
		return nil, nil, errors.New("invalid header length")
	}
	hraw := raw[len(FileMagic)+4 : len(FileMagic)+4+int(hlen)]
	ciphertext := raw[len(FileMagic)+4+int(hlen):]
	if len(ciphertext) == 0 {
		return nil, nil, errors.New("empty ciphertext")
	}

	header := &FileHeader{}
	if err := json.Unmarshal(hraw, header); err != nil {
		return nil, nil, err
	}
	if header.Version != FileVersion {
		return nil, nil, fmt.Errorf("unsupported vault version: %d", header.Version)
	}
	return header, ciphertext, nil
}

func packFile(header *FileHeader, ciphertext []byte) ([]byte, error) {
	hraw, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(FileMagic)+4+len(hraw)+len(ciphertext))
	buf = append(buf, []byte(FileMagic)...)
	hlen := make([]byte, 4)
	binary.BigEndian.PutUint32(hlen, uint32(len(hraw)))
	buf = append(buf, hlen...)
	buf = append(buf, hraw...)
	buf = append(buf, ciphertext...)
	return buf, nil
}

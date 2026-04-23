package terminalinput

import (
	"errors"
	"io"
	"testing"
)

func TestReadSecretRawReturnsOnEnter(t *testing.T) {
	got, err := readSecretRaw(bytesReader("s3cr3t\r"))
	if err != nil {
		t.Fatalf("readSecretRaw returned error: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("unexpected secret: %q", string(got))
	}
}

func TestReadSecretRawHandlesBackspace(t *testing.T) {
	got, err := readSecretRaw(bytesReader("ab" + string([]byte{keyBackspace}) + "c\r"))
	if err != nil {
		t.Fatalf("readSecretRaw returned error: %v", err)
	}
	if string(got) != "ac" {
		t.Fatalf("unexpected secret: %q", string(got))
	}
}

func TestReadSecretRawInterruptsOnCtrlC(t *testing.T) {
	_, err := readSecretRaw(bytesReader("ab" + string([]byte{keyCtrlC})))
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
}

type byteReader struct {
	data []byte
	pos  int
}

func bytesReader(v string) *byteReader {
	return &byteReader{data: []byte(v)}
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

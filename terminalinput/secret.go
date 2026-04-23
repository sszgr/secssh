package terminalinput

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

const (
	keyCtrlC     = byte(3)
	keyBackspace = byte(8)
	keyDelete    = byte(127)
	keyCR        = byte('\r')
	keyLF        = byte('\n')
)

var ErrInterrupted = errors.New("input interrupted")

func ReadSecret(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stdout, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fd := int(os.Stdin.Fd())
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = term.Restore(fd, oldState)
			fmt.Fprintln(os.Stdout)
		}()

		pw, err := readSecretRaw(os.Stdin)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(pw), nil
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace([]byte(line)), nil
}

func readSecretRaw(r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			switch buf[0] {
			case keyCtrlC:
				return nil, ErrInterrupted
			case keyBackspace, keyDelete:
				if len(out) > 0 {
					out = out[:len(out)-1]
				}
			case keyCR, keyLF:
				return out, nil
			default:
				out = append(out, buf[0])
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
	}
}

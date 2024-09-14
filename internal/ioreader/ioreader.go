package ioreader

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

type Reader interface {
	ReadString(prompt string) (string, error)
	ReadPassword(prompt string) (string, error)
}

type ioReader struct {
	Stdin io.Reader
}

var _ Reader = (*ioReader)(nil)

func New() *ioReader {
	return &ioReader{
		Stdin: os.Stdin,
	}
}

// ReadString reads a string from the stdin.
func (ir *ioReader) ReadString(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", fmt.Errorf("write error: %w", err)
	}

	r := bufio.NewReader(ir.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}

	s = strings.TrimRight(s, "\r\n")

	return s, nil
}

// ReadPassword reads a password from the stdin without echo back.
func (*ioReader) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", fmt.Errorf("write error: %w", err)
	}

	b, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}

	if _, err := fmt.Fprintln(os.Stderr); err != nil {
		return "", fmt.Errorf("write error: %w", err)
	}

	return string(b), nil
}

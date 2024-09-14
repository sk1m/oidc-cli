package browser

import (
	"context"
	"os"
	"os/exec"

	"github.com/pkg/browser"
)

type Opener interface {
	Open(url string) error
	OpenCommand(ctx context.Context, url, command string) error
}

type Browser struct{}

var _ Opener = (*Browser)(nil)

func New() *Browser {
	return &Browser{}
}

// Open opens the default browser.
func (*Browser) Open(url string) error {
	return browser.OpenURL(url)
}

// OpenCommand opens the browser using the command.
func (*Browser) OpenCommand(ctx context.Context, url, command string) error {
	c := exec.CommandContext(ctx, command, url)
	c.Stdout = os.Stderr // see above
	c.Stderr = os.Stderr
	return c.Run()
}

package authctl

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

type BrowserOpts struct {
	SkipOpenBrowser bool
	BrowserCommand  string
}

func (s *Service) openURL(ctx context.Context, url string, opts *BrowserOpts) {
	if opts.SkipOpenBrowser {
		s.logger.Printf("Please visit the following URL in your browser: %s", url)
		return
	}

	s.logger.Infof("opening %s in the browser", url)
	if opts.BrowserCommand != "" {
		if err := s.browser.OpenCommand(ctx, url, opts.BrowserCommand); err != nil {
			s.logger.Errorf(`could not open the browser: %s

Please visit the following URL in your browser manually: %s`, err, url)
		}
		return
	}
	if err := s.browser.Open(url); err != nil {
		s.logger.Errorf(`could not open the browser: %s

Please visit the following URL in your browser manually: %s`, err, url)
	}
}

func browserRedirectHTML(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return fmt.Sprintf(`invalid URL is set: %s`, err)
	}

	return fmt.Sprintf(`
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta http-equiv="refresh" content="0;URL=%s">
				<meta charset="UTF-8">
				<title>Authenticated</title>
			</head>
			<body>
				<a href="%s">redirecting...</a>
			</body>
			</html>
		`,
		targetURL,
		targetURL,
	)
}

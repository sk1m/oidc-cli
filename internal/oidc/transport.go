package oidc

import (
	"net/http"
	"net/http/httputil"

	"github.com/sk1m/oidc-cli/internal/logger"
)

type Transport struct {
	Base   http.RoundTripper
	Logger logger.LogWriter
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.Logger.ShouldLevel(logger.TraceLevel) {
		return t.Base.RoundTrip(req)
	}

	reqDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		t.Logger.Tracef("could not dump the request: %s", err)
		return t.Base.RoundTrip(req)
	}
	t.Logger.Tracef("%s", string(reqDump))
	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Logger.Tracef("could not dump the response: %s", err)
		return resp, err
	}
	t.Logger.Tracef("%s", string(respDump))
	return resp, err
}

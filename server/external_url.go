package server

import (
	"fmt"
	"net/url"
	"strings"
)

// normalizeExternalURL validates Options.ExternalURL and returns it as a bare
// scheme://host[:port] prefix. A path is refused rather than prepended: clients
// sign the path they request, so a proxy that strips a prefix before the
// request reaches this server breaks every signature.
func normalizeExternalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil {
		return "", fmt.Errorf("external URL %q: %w", raw, err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", fmt.Errorf("external URL %q: scheme must be http or https", raw)
	case u.Host == "":
		return "", fmt.Errorf("external URL %q: no host", raw)
	case u.User != nil:
		return "", fmt.Errorf("external URL %q: must not carry credentials", raw)
	case u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return "", fmt.Errorf("external URL %q: must be scheme://host[:port] only; serve the API at the root of the host, since a stripped path prefix breaks request signatures", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

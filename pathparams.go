package caddyhttp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type (

	// MatchPathPARAMS matches requests by the URI's path (case-insensitive).
	// Path matches are exact while simple placeholders
	// /api/v1/resource/:resourceid
	MatchPathParams []string
)

func init() {
	caddy.RegisterModule(MatchPathParams{})
}

// CaddyModule returns the Caddy module information.
func (MatchPathParams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.pathparams",
		New: func() caddy.Module { return new(MatchPathParams) },
	}
}

// Provision lower-cases the paths in m to ensure case-insensitive matching.
func (m MatchPathParams) Provision(_ caddy.Context) error {
	// m.logger = ctx.Logger(m)
	for i := range m {
		m[i] = strings.ToLower(m[i])
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchPathParams) Match(r *http.Request) bool {
	lowerPath := strings.ToLower(r.URL.Path)
	// fmt.Println("matching..")
	// m.logger.Error("matching...")

	// see #2917; Windows ignores trailing dots and spaces
	// when accessing files (sigh), potentially causing a
	// security risk (cry) if PHP files end up being served
	// as static files, exposing the source code, instead of
	// being matched by *.php to be treated as PHP scripts
	lowerPath = strings.TrimRight(lowerPath, ". ")

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

outer:
	for _, matchPath := range m {
		matchPath = repl.ReplaceAll(matchPath, "")
		// fmt.Println(lowerPath)
		// fmt.Println(matchPath)

		if len(lowerPath) > 1 && strings.HasPrefix(lowerPath, "/") {

			lowerPathSplit := strings.Split(lowerPath[1:], "/")
			matchPathSplit := strings.Split(matchPath[1:], "/")

			if len(lowerPathSplit) == len(matchPathSplit) { // Only exact match of segments (Can be changed to >= for open ended matching)
				for a, bla := range matchPathSplit {
					bly := lowerPathSplit[a]
					// fmt.Println(fmt.Sprintf("Check match: %d %s = %s", a, bla, bly))

					if len(bla) > 1 && strings.HasPrefix(bla, ":") {
						// fmt.Println(fmt.Sprintf("path param: %s, value: %s", bla, bly))
						pathParamName := bla[1:]
						key := fmt.Sprintf("%s.%s", "http.matchers.pathparams", pathParamName)
						repl.Set(key, bly)
					} else {
						if bla != bly {
							// fmt.Println(fmt.Sprintf("Not matching %s, breaking to the next", lowerPath))
							break outer
						}
					}
				}
				// appearantly all segments match!
				return true
			}
		}
	}
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchPathParams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		*m = append(*m, d.RemainingArgs()...)
		if d.NextBlock(0) {
			return d.Err("malformed path matcher: blocks are not supported")
		}
	}
	return nil
}

// Interface guards
var (
	_ caddyhttp.RequestMatcher = (*MatchPathParams)(nil)
	_ caddy.Provisioner        = (*MatchPathParams)(nil)
)

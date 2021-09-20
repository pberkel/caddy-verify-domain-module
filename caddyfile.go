package verifydomain

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("verify_domain", parseCaddyfile)
}

// parseCaddyfile unmarshals tokens from h into a new VerifyDomain
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	v := new(VerifyDomain)
	err := v.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (v *VerifyDomain) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "ask":
				if !d.Args(&v.Ask) {
					return d.ArgErr()
				}
			case "port":
				if !d.Args(&v.Port) {
					return d.ArgErr()
				}
			case "salt":
				if !d.Args(&v.Salt) {
					return d.ArgErr()
				}
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*VerifyDomain)(nil)
)

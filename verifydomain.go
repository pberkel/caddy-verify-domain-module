package verifydomain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

// Global configuration variable
var cfg *Config

func init() {
	caddy.RegisterModule(VerifyDomain{})
	httpcaddyfile.RegisterHandlerDirective("verify_domain", parseCaddyfile)
}

type Config struct {
	Listen string `json:"listen_url,omitempty"`
	Port   string `json:"challenge_port,omitempty"`
	Salt   string `json:"challenge_salt,omitempty"`
}

type VerifyDomain struct {
	Config
	Listen     string `json:"listen_url,omitempty"`
	Port       string `json:"challenge_port,omitempty"`
	Salt       string `json:"challenge_salt,omitempty"`
	logger     *zap.Logger
	client     *http.Client
	listenUrl  *url.URL
	verifyPort string
}

// CaddyModule returns the Caddy module information
func (VerifyDomain) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.verify_domain",
		New: func() caddy.Module { return new(VerifyDomain) },
	}
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
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "listen_url":
				if !d.Args(&v.Listen) {
					return d.ArgErr()
				}
			case "challenge_port":
				if !d.Args(&v.Port) {
					return d.ArgErr()
				}
			case "challenge_salt":
				if !d.Args(&v.Salt) {
					return d.ArgErr()
				}
			}
		}
	}
	return nil
}

// Provision VerifyDomain configuration
func (vd *VerifyDomain) Provision(ctx caddy.Context) error {
	vd.logger = ctx.Logger(vd)
	vd.client = &http.Client{
		Timeout: time.Duration(1) * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// Check for global config
	if cfg == nil {
		// No global config defined yet, create new one
		cfg = &vd.Config
	} else {
		// A global config is defined, always use it
		vd.Config = *cfg
	}
	// Listen URL not provided, check for globally defined one
	if vd.Listen == "" {
		if vd.Config.Listen == "" {
			// load TLS Automation OnDemand Listen URL
			if tlsAppIface, err := ctx.App("tls"); err == nil {
				tlsApp := tlsAppIface.(*caddytls.TLS)
				if tlsApp.Automation != nil && tlsApp.Automation.OnDemand != nil && tlsApp.Automation.OnDemand.Ask != "" {
					vd.Config.Listen = tlsApp.Automation.OnDemand.Ask
				}
			}
		}
		vd.Listen = vd.Config.Listen
	}
	vd.logger.Debug("Listen: " + vd.Listen)
	// Salt not provided, check for globally defined one
	if vd.Salt == "" {
		if vd.Config.Salt == "" {
			// No global salt, generate one automatically
			vd.Config.Salt = generateSalt(8)
		}
		vd.Salt = vd.Config.Salt
	}
	vd.logger.Debug("Salt: " + vd.Salt)
	return nil
}

// Validate implements caddy.Validator
func (vd *VerifyDomain) Validate() error {
	var err error
	if vd.Listen != "" {
		vd.listenUrl, err = url.ParseRequestURI(vd.Listen)
		if err != nil {
			return err
		}
	}
	// Make sure port is actually a valid integer
	if _, err := strconv.Atoi(vd.Port); err == nil {
		vd.verifyPort = ":" + vd.Port
	}
	return nil
}

func (vd VerifyDomain) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// Handle verification check response
	if reqHash := r.Header.Get("X-Caddy-Verification-Request"); reqHash != "" {
		if reqHash == generateHash(r.Host, vd.Salt, true) {
			resHash := generateHash(r.Host, vd.Salt, false)
			w.Header().Set("X-Caddy-Verification-Response", resHash)
		}
	}

	// Handle verification check request
	if vd.listenUrl != nil {
		// Host may not specified if Listen URL was configured as an absolute path
		if (vd.listenUrl.Host == "" || r.Host == vd.listenUrl.Host) && r.URL.Path == vd.listenUrl.Path && r.URL.Query().Has("domain") {
			domain := r.URL.Query().Get("domain")
			respCode, respMsg := vd.verifyDomain(domain)
			http.Error(w, respMsg, respCode)
			return nil
		}
	}

	return next.ServeHTTP(w, r)
}

func (vd *VerifyDomain) verifyDomain(domain string) (int, string) {

	// reject IPv4 or IPv6 addresses
	if net.ParseIP(domain) != nil {
		return http.StatusBadRequest, "Domain cannot be an IP address"
	}

	// reject domains resolving to private, loopback and unspecified IP addresses
	ips, err := net.LookupIP(domain)
	if err != nil {
		return http.StatusBadRequest, "Cannot resolve domain"
	}
	for _, ip := range ips {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return http.StatusBadRequest, "Domain resolves to a private or loopback IP address"
		}
	}

	// construct validation request
	host := domain + vd.verifyPort
	creq, err := http.NewRequest("GET", "http://"+host+"/", nil)
	if err != nil {
		return http.StatusBadRequest, "Error creating HTTP verification request"
	}
	// set validation request header
	creq.Header.Set("X-Caddy-Verification-Request", generateHash(host, vd.Salt, true))
	cres, err := vd.client.Do(creq)
	if err != nil {
		return http.StatusBadRequest, "Error completing HTTP verification request"
	}
	// verify validation response header
	if cres.Header.Get("X-Caddy-Verification-Response") != generateHash(host, vd.Salt, false) {
		return http.StatusBadRequest, "Invalid or missing verification response"
	}

	// domain successfully verified
	return http.StatusOK, "Domain verified"
}

func generateHash(input string, salt string, saltFirst bool) string {
	var data []byte
	if saltFirst {
		data = []byte(salt + input)
	} else {
		data = []byte(input + salt)
	}
	output := sha256.Sum256(data)
	return hex.EncodeToString(output[:4])
}

func generateSalt(length int) string {
	random := make([]byte, 32)
	_, err := rand.Read(random)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(random)[:length]
}

// Interface guards
var (
	_ caddy.Provisioner           = (*VerifyDomain)(nil)
	_ caddy.Validator             = (*VerifyDomain)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyDomain)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyDomain)(nil)
)

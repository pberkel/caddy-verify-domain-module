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
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

// Global configuration variable
var cfg *GlobalConfig

func init() {
	caddy.RegisterModule(VerifyDomain{})
}

type GlobalConfig struct {
	Ask  string `json:"ask,omitempty"`
	Port string `json:"port,omitempty"`
	Salt string `json:"salt,omitempty"`
}

type VerifyDomain struct {
	GlobalConfig
	Ask        string `json:"ask,omitempty"`
	Port       string `json:"port,omitempty"`
	Salt       string `json:"salt,omitempty"`
	logger     *zap.Logger
	client     *http.Client
	askUrl     *url.URL
	verifyPort string
}

// CaddyModule returns the Caddy module information
func (VerifyDomain) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.verify_domain",
		New: func() caddy.Module { return new(VerifyDomain) },
	}
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
		cfg = &vd.GlobalConfig
	} else {
		// A global config is defined, always use it
		vd.GlobalConfig = *cfg
	}
	// Ask URL not provided, check for globally defined one
	if vd.Ask == "" {
		if vd.GlobalConfig.Ask == "" {
			// load TLS Automation OnDemand Ask URL
			if tlsAppIface, err := ctx.App("tls"); err == nil {
				tlsApp := tlsAppIface.(*caddytls.TLS)
				if tlsApp.Automation != nil && tlsApp.Automation.OnDemand != nil && tlsApp.Automation.OnDemand.Ask != "" {
					vd.GlobalConfig.Ask = tlsApp.Automation.OnDemand.Ask
				}
			}
		}
		vd.Ask = vd.GlobalConfig.Ask
	}
	// Salt not provided, check for globally defined one
	if vd.Salt == "" {
		if vd.GlobalConfig.Salt == "" {
			// No global salt, generate one automatically
			vd.GlobalConfig.Salt = generateSalt(8)
		}
		vd.Salt = vd.GlobalConfig.Salt
	}
	return nil
}

// Validate implements caddy.Validator
func (vd *VerifyDomain) Validate() error {
	var err error
	if vd.Ask != "" {
		vd.askUrl, err = url.ParseRequestURI(vd.Ask)
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
	if vd.askUrl != nil {
		// Host may not specified if Ask URL was configured as an absolute path
		if (vd.askUrl.Host == "" || r.Host == vd.askUrl.Host) && r.URL.Path == vd.askUrl.Path && r.URL.Query().Has("domain") {
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
)

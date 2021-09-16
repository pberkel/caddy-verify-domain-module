package verifydomain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(VerifyDomain{})
}

type VerifyDomain struct {
	Ask          string `json:"ask,omitempty"`
	Port         string `json:"port,omitempty"`
	RequestSalt  string `json:"request_salt,omitempty"`
	ResponseSalt string `json:"response_salt,omitempty"`
	logger       *zap.Logger
	client       *http.Client
	askUrl       *url.URL
	verifyPort   string
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
	return nil
}

// Validate implements caddy.Validator
func (vd *VerifyDomain) Validate() error {
	var err error
	if vd.Ask == "" {
		return fmt.Errorf("No Ask URL configured")
	}
	vd.askUrl, err = url.Parse(vd.Ask)
	if err != nil {
		return err
	}
	// make sure port is actually a valid integer
	if _, err := strconv.Atoi(vd.Port); err == nil {
		vd.verifyPort = ":" + vd.Port
	} else {
		// if port not explicitly defined, use port from ask URL
		if vd.askUrl.Port() != "" {
			vd.verifyPort = ":" + vd.askUrl.Port()
		}
	}
	// RequestSalt not provided, automatically generate one
	if vd.RequestSalt == "" {
		vd.RequestSalt = generateSalt(10)
	}
	// ResponseSalt not provided, automatically generate one
	if vd.ResponseSalt == "" {
		vd.ResponseSalt = generateSalt(10)
	}
	return nil
}

// Cleanup resources made during provisioning
func (vd *VerifyDomain) Cleanup() error {
	return nil
}

func (vd VerifyDomain) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// Handle verification check response
	if r.Header.Get("X-Caddy-Validation-Request") == generateHash(r.Host, vd.RequestSalt) {
		hash := generateHash(r.Host, vd.ResponseSalt)
		w.Header().Set("X-Caddy-Validation-Response", hash)
	}

	// Handle verification check request
	if r.Host == vd.askUrl.Host && r.URL.Path == vd.askUrl.Path && r.URL.Query().Has("domain") {
		domain := r.URL.Query().Get("domain")
		respCode, respMsg := vd.verifyDomain(domain)
		http.Error(w, respMsg, respCode)
		return nil
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
	creq.Header.Set("X-Caddy-Validation-Request", generateHash(host, vd.RequestSalt))
	cres, err := vd.client.Do(creq)
	if err != nil {
		return http.StatusBadRequest, "Error completing HTTP verification request"
	}
	// verify validation response header
	if cres.Header.Get("X-Caddy-Validation-Response") != generateHash(host, vd.ResponseSalt) {
		return http.StatusBadRequest, "Invalid or missing verification response"
	}

	// domain successfully verified
	return http.StatusOK, "Domain verified"
}

func generateHash(input string, salt string) string {
	data := sha256.Sum256([]byte(salt + input))
	return hex.EncodeToString(data[:4])
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
	_ caddy.CleanerUpper          = (*VerifyDomain)(nil)
	_ caddy.Validator             = (*VerifyDomain)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyDomain)(nil)
)

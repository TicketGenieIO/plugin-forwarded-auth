package plugin_forwardedauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	xForwardedURI     = "X-Forwarded-Uri"
	xForwardedMethod  = "X-Forwarded-Method"
	forwardedTypeName = "ForwardedAuthType"
)

const (
	connectionHeader = "Connection"
	upgradeHeader    = "Upgrade"
)

// HeaderValuesContainsToken reports whether any string in values
// contains the provided token, ASCII case-insensitively.
func HeaderValuesContainsToken(values []string, token string) bool {
	for _, v := range values {
		if headerValueContainsToken(v, token) {
			return true
		}
	}
	return false
}

// trimOWS returns x with all optional whitespace removes from the
// beginning and end.
func trimOWS(x string) string {
	// TODO: consider using strings.Trim(x, " \t") instead,
	// if and when it's fast enough. See issue 10292.
	// But this ASCII-only code will probably always beat UTF-8
	// aware code.
	for len(x) > 0 && isOWS(x[0]) {
		x = x[1:]
	}
	for len(x) > 0 && isOWS(x[len(x)-1]) {
		x = x[:len(x)-1]
	}
	return x
}

// isOWS reports whether b is an optional whitespace byte, as defined
// by RFC 7230 section 3.2.3.
func isOWS(b byte) bool { return b == ' ' || b == '\t' }

// headerValueContainsToken reports whether v (assumed to be a
// 0#element, in the ABNF extension described in RFC 7230 section 7)
// contains token amongst its comma-separated tokens, ASCII
// case-insensitively.
func headerValueContainsToken(v string, token string) bool {
	for comma := strings.IndexByte(v, ','); comma != -1; comma = strings.IndexByte(v, ',') {
		if tokenEqual(trimOWS(v[:comma]), token) {
			return true
		}
		v = v[comma+1:]
	}
	return tokenEqual(trimOWS(v), token)
}

// lowerASCII returns the ASCII lowercase version of b.
func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// tokenEqual reports whether t1 and t2 are equal, ASCII case-insensitively.
func tokenEqual(t1, t2 string) bool {
	if len(t1) != len(t2) {
		return false
	}
	for i, b := range t1 {
		if b >= utf8.RuneSelf {
			// No UTF-8 or non-ASCII allowed in tokens.
			return false
		}
		if lowerASCII(byte(b)) != lowerASCII(t2[i]) {
			return false
		}
	}
	return true
}

// Remover removes hop-by-hop headers listed in the "Connection" header.
// See RFC 7230, section 6.1.
func Remover(next http.Handler) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		var reqUpType string
		if HeaderValuesContainsToken(req.Header[connectionHeader], upgradeHeader) {
			reqUpType = req.Header.Get(upgradeHeader)
		}

		removeConnectionHeaders(req.Header)

		if reqUpType != "" {
			req.Header.Set(connectionHeader, upgradeHeader)
			req.Header.Set(upgradeHeader, reqUpType)
		} else {
			req.Header.Del(connectionHeader)
		}

		next.ServeHTTP(rw, req)
	}
}

func removeConnectionHeaders(h http.Header) {
	for _, f := range h[connectionHeader] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

// X-* Header names.
const (
	XForwardedProto  = "X-Forwarded-Proto"
	XForwardedFor    = "X-Forwarded-For"
	XForwardedHost   = "X-Forwarded-Host"
	XForwardedPort   = "X-Forwarded-Port"
	XForwardedServer = "X-Forwarded-Server"
	XRealIP          = "X-Real-Ip"
)

// Headers names.
const (
	Connection         = "Connection"
	KeepAlive          = "Keep-Alive"
	ProxyAuthenticate  = "Proxy-Authenticate"
	ProxyAuthorization = "Proxy-Authorization"
	Te                 = "Te" // canonicalized version of "TE"
	Trailers           = "Trailers"
	TransferEncoding   = "Transfer-Encoding"
	Upgrade            = "Upgrade"
	ContentLength      = "Content-Length"
)

// hopHeaders Hop-by-hop headers to be removed in the authentication request.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
// Proxy-Authorization header is forwarded to the authentication server (see https://tools.ietf.org/html/rfc7235#section-4.4).
var hopHeaders = []string{
	Connection,
	KeepAlive,
	Te, // canonicalized version of "TE"
	Trailers,
	TransferEncoding,
	Upgrade,
}

// +k8s:deepcopy-gen=true

// ClientTLS holds TLS specific configurations as client
// CA, Cert and Key can be either path or file contents.
type ClientTLS struct {
	CA                 string `description:"TLS CA" json:"ca,omitempty" toml:"ca,omitempty" yaml:"ca,omitempty"`
	Cert               string `description:"TLS cert" json:"cert,omitempty" toml:"cert,omitempty" yaml:"cert,omitempty"`
	Key                string `description:"TLS key" json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty" loggable:"false"`
	InsecureSkipVerify bool   `description:"TLS insecure skip verify" json:"insecureSkipVerify,omitempty" toml:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty" export:"true"`
}

// CreateTLSConfig creates a TLS config from ClientTLS structures.
func (c *ClientTLS) CreateTLSConfig(ctx context.Context) (*tls.Config, error) {
	if c == nil {
		return nil, nil
	}

	// Not initialized, to rely on system bundle.
	var caPool *x509.CertPool

	if c.CA != "" {
		var ca []byte
		if _, errCA := os.Stat(c.CA); errCA == nil {
			var err error
			ca, err = os.ReadFile(c.CA)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA. %w", err)
			}
		} else {
			ca = []byte(c.CA)
		}

		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(ca) {
			return nil, errors.New("failed to parse CA")
		}
	}

	hasCert := len(c.Cert) > 0
	hasKey := len(c.Key) > 0

	if hasCert != hasKey {
		return nil, errors.New("both TLS cert and key must be defined")
	}

	if !hasCert || !hasKey {
		return &tls.Config{
			RootCAs:            caPool,
			InsecureSkipVerify: c.InsecureSkipVerify,
		}, nil
	}

	cert, err := loadKeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}, nil
}

func loadKeyPair(cert, key string) (tls.Certificate, error) {
	keyPair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err == nil {
		return keyPair, nil
	}

	_, err = os.Stat(cert)
	if err != nil {
		return tls.Certificate{}, errors.New("cert file does not exist")
	}

	_, err = os.Stat(key)
	if err != nil {
		return tls.Certificate{}, errors.New("key file does not exist")
	}

	keyPair, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
}

// +k8s:deepcopy-gen=true

// Config holds the forward auth middleware configuration.
// This middleware delegates the request authentication to a Service.
// More info: https://doc.traefik.io/traefik/v3.0/middlewares/http/forwardauth/
type Config struct {
	// Address defines the authentication server address.
	Address string `json:"address,omitempty" toml:"address,omitempty" yaml:"address,omitempty"`
	// TLS defines the configuration used to secure the connection to the authentication server.
	TLS *ClientTLS `json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty" export:"true"`
	// TrustForwardHeader defines whether to trust (ie: forward) all X-Forwarded-* headers.
	TrustForwardHeader bool `json:"trustForwardHeader,omitempty" toml:"trustForwardHeader,omitempty" yaml:"trustForwardHeader,omitempty" export:"true"`
	ShouldForwardBody  bool `json:"shouldForwardBody,omitempty" toml:"shouldForwardBody,omitempty" yaml:"shouldForwardBody,omitempty" export:"true"`
	// AuthResponseHeaders defines the list of headers to copy from the authentication server response and set on forwarded request, replacing any existing conflicting headers.
	AuthResponseHeaders []string `json:"authResponseHeaders,omitempty" toml:"authResponseHeaders,omitempty" yaml:"authResponseHeaders,omitempty" export:"true"`
	// AuthResponseHeadersRegex defines the regex to match headers to copy from the authentication server response and set on forwarded request, after stripping all headers that match the regex.
	// More info: https://doc.traefik.io/traefik/v3.0/middlewares/http/forwardauth/#authresponseheadersregex
	AuthResponseHeadersRegex string `json:"authResponseHeadersRegex,omitempty" toml:"authResponseHeadersRegex,omitempty" yaml:"authResponseHeadersRegex,omitempty" export:"true"`
	// AuthRequestHeaders defines the list of the headers to copy from the request to the authentication server.
	// If not set or empty then all request headers are passed.
	AuthRequestHeaders []string `json:"authRequestHeaders,omitempty" toml:"authRequestHeaders,omitempty" yaml:"authRequestHeaders,omitempty" export:"true"`
}

func CreateConfig() *Config {
	return &Config{}
}

type logWriter struct {
}

func (w *logWriter) info(m string) {
	_, _ = os.Stdout.WriteString(m)
}

func (w *logWriter) error(m string) {
	_, _ = os.Stderr.WriteString(m)
}

type forwardAuth struct {
	address                  string
	authResponseHeaders      []string
	authResponseHeadersRegex *regexp.Regexp
	next                     http.Handler
	name                     string
	client                   http.Client
	trustForwardHeader       bool
	authRequestHeaders       []string
	logger                   *logWriter
	shouldForwardBody        bool
}

// New creates a forward auth middleware.
func New(ctx context.Context, next http.Handler, config Config, name string) (http.Handler, error) {
	fa := &forwardAuth{
		address:             config.Address,
		authResponseHeaders: config.AuthResponseHeaders,
		next:                next,
		name:                name,
		trustForwardHeader:  config.TrustForwardHeader,
		authRequestHeaders:  config.AuthRequestHeaders,
		logger:              &logWriter{},
		shouldForwardBody:   config.ShouldForwardBody,
	}

	// Ensure our request client does not follow redirects
	fa.client = http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	if config.TLS != nil {
		tlsConfig, err := config.TLS.CreateTLSConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to create client TLS configuration: %w", err)
		}

		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		fa.client.Transport = tr
	}

	if config.AuthResponseHeadersRegex != "" {
		re, err := regexp.Compile(config.AuthResponseHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regular expression %s: %w", config.AuthResponseHeadersRegex, err)
		}
		fa.authResponseHeadersRegex = re
	}

	return Remover(fa), nil
}

func (fa *forwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var forwardedBody io.Reader
	if fa.shouldForwardBody {
		forwardedBody = req.Body
	}

	forwardReq, err := http.NewRequest(http.MethodGet, fa.address, forwardedBody)
	if err != nil {
		logMessage := fmt.Sprintf("Error calling %s. Cause %s", fa.address, err)
		fa.logger.info(logMessage)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	writeHeader(req, forwardReq, fa.trustForwardHeader, fa.authRequestHeaders)

	forwardResponse, forwardErr := fa.client.Do(forwardReq)
	if forwardErr != nil {
		logMessage := fmt.Sprintf("Error calling %s. Cause: %s", fa.address, forwardErr)
		fa.logger.info(logMessage)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, readError := io.ReadAll(forwardResponse.Body)
	if readError != nil {
		logMessage := fmt.Sprintf("Error reading body %s. Cause: %s", fa.address, readError)
		fa.logger.info(logMessage)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer forwardResponse.Body.Close()

	// Pass the forward response's body and selected headers if it
	// didn't return a response within the range of [200, 300).
	if forwardResponse.StatusCode < http.StatusOK || forwardResponse.StatusCode >= http.StatusMultipleChoices {
		fa.logger.info(fmt.Sprintf("Remote error %s. StatusCode: %d", fa.address, forwardResponse.StatusCode))

		CopyHeaders(rw.Header(), forwardResponse.Header)
		RemoveHeaders(rw.Header(), hopHeaders...)

		// Grab the location header, if any.
		redirectURL, err := forwardResponse.Location()

		if err != nil {
			if !errors.Is(err, http.ErrNoLocation) {
				logMessage := fmt.Sprintf("Error reading response location header %s. Cause: %s", fa.address, err)
				fa.logger.info(logMessage)

				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else if redirectURL.String() != "" {
			// Set the location in our response if one was sent back.
			rw.Header().Set("Location", redirectURL.String())
		}

		rw.WriteHeader(forwardResponse.StatusCode)

		if _, err = rw.Write(body); err != nil {
			fa.logger.error(err.Error())
		}
		return
	}

	for _, headerName := range fa.authResponseHeaders {
		headerKey := http.CanonicalHeaderKey(headerName)
		req.Header.Del(headerKey)
		if len(forwardResponse.Header[headerKey]) > 0 {
			req.Header[headerKey] = append([]string(nil), forwardResponse.Header[headerKey]...)
		}
	}

	if fa.authResponseHeadersRegex != nil {
		for headerKey := range req.Header {
			if fa.authResponseHeadersRegex.MatchString(headerKey) {
				req.Header.Del(headerKey)
			}
		}

		for headerKey, headerValues := range forwardResponse.Header {
			if fa.authResponseHeadersRegex.MatchString(headerKey) {
				req.Header[headerKey] = append([]string(nil), headerValues...)
			}
		}
	}

	req.RequestURI = req.URL.RequestURI()
	fa.next.ServeHTTP(rw, req)
}

// CopyHeaders copies http headers from source to destination, it
// does not override, but adds multiple headers.
func CopyHeaders(dst http.Header, src http.Header) {
	for k, vv := range src {
		dst[k] = append(dst[k], vv...)
	}
}

// RemoveHeaders removes the header with the given names from the headers map.
func RemoveHeaders(headers http.Header, names ...string) {
	for _, h := range names {
		headers.Del(h)
	}
}

func writeHeader(req, forwardReq *http.Request, trustForwardHeader bool, allowedHeaders []string) {
	CopyHeaders(forwardReq.Header, req.Header)
	RemoveHeaders(forwardReq.Header, hopHeaders...)

	forwardReq.Header = filterForwardRequestHeaders(forwardReq.Header, allowedHeaders)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if trustForwardHeader {
			if prior, ok := req.Header[XForwardedFor]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
		}
		forwardReq.Header.Set(XForwardedFor, clientIP)
	}

	xMethod := req.Header.Get(xForwardedMethod)
	switch {
	case xMethod != "" && trustForwardHeader:
		forwardReq.Header.Set(xForwardedMethod, xMethod)
	case req.Method != "":
		forwardReq.Header.Set(xForwardedMethod, req.Method)
	default:
		forwardReq.Header.Del(xForwardedMethod)
	}

	xfp := req.Header.Get(XForwardedProto)
	switch {
	case xfp != "" && trustForwardHeader:
		forwardReq.Header.Set(XForwardedProto, xfp)
	case req.TLS != nil:
		forwardReq.Header.Set(XForwardedProto, "https")
	default:
		forwardReq.Header.Set(XForwardedProto, "http")
	}

	if xfp := req.Header.Get(XForwardedPort); xfp != "" && trustForwardHeader {
		forwardReq.Header.Set(XForwardedPort, xfp)
	}

	xfh := req.Header.Get(XForwardedHost)
	switch {
	case xfh != "" && trustForwardHeader:
		forwardReq.Header.Set(XForwardedHost, xfh)
	case req.Host != "":
		forwardReq.Header.Set(XForwardedHost, req.Host)
	default:
		forwardReq.Header.Del(XForwardedHost)
	}

	xfURI := req.Header.Get(xForwardedURI)
	switch {
	case xfURI != "" && trustForwardHeader:
		forwardReq.Header.Set(xForwardedURI, xfURI)
	case req.URL.RequestURI() != "":
		forwardReq.Header.Set(xForwardedURI, req.URL.RequestURI())
	default:
		forwardReq.Header.Del(xForwardedURI)
	}
}

func filterForwardRequestHeaders(forwardRequestHeaders http.Header, allowedHeaders []string) http.Header {
	if len(allowedHeaders) == 0 {
		return forwardRequestHeaders
	}

	filteredHeaders := http.Header{}
	for _, headerName := range allowedHeaders {
		values := forwardRequestHeaders.Values(headerName)
		if len(values) > 0 {
			filteredHeaders[http.CanonicalHeaderKey(headerName)] = append([]string(nil), values...)
		}
	}

	return filteredHeaders
}

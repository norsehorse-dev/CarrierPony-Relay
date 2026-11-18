// Package api is the relay's HTTP interface: the same endpoints, status codes
// and JSON the PHP relay answered with.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/store"
)

// Server answers relay requests.
type Server struct {
	cfg    config.Config
	store  *store.Store
	now    func() time.Time
	routes map[string]route
}

type handler func(s *Server, r *http.Request, in input) result

type route struct {
	handle handler
	// large marks the two endpoints that take an envelope. Their bodies may be
	// as big as the largest envelope allows; every other body is small.
	large bool
}

// smallBody is the most any endpoint without an envelope reads. The largest
// legitimate one is a report, a few hundred kilobytes at the outside.
const smallBody = 1 << 20

// New builds a server over an open store.
func New(cfg config.Config, st *store.Store) *Server {
	s := &Server{cfg: cfg, store: st, now: time.Now}
	s.routes = map[string]route{
		"/v1/challenge":                 {handle: (*Server).challenge},
		"/v1/register-device":           {handle: notPorted},
		"/v1/send":                      {handle: notPorted, large: true},
		"/v1/inbox":                     {handle: notPorted},
		"/v1/ack":                       {handle: notPorted},
		"/v1/register-push":             {handle: notPorted},
		"/v1/register-wake":             {handle: notPorted},
		"/v1/report":                    {handle: notPorted},
		"/v1/pair/offer":                {handle: notPorted},
		"/v1/pair/accept":               {handle: notPorted},
		"/v1/pair/status":               {handle: notPorted},
		"/v1/sealed/register-device":    {handle: notPorted},
		"/v1/sealed/register-mailboxes": {handle: notPorted},
		"/v1/sealed/send":               {handle: notPorted, large: true},
		"/v1/sealed/inbox":              {handle: notPorted},
		"/v1/sealed/ack":                {handle: notPorted},
	}
	return s
}

// notPorted answers for an endpoint the Go relay does not serve yet. It goes
// away when the last endpoint is ported.
func notPorted(*Server, *http.Request, input) result {
	return fail(http.StatusNotImplemented, "not_implemented")
}

// maxEnvelopeBody is the largest body an envelope endpoint reads: the biggest
// envelope in base64, plus room for the JSON around it.
func (s *Server) maxEnvelopeBody() int64 {
	return int64(math.Ceil(float64(s.cfg.Limits.MaxEnvelopeBytes)*4/3)) + 65536
}

// ServeHTTP routes a request. Only POST to a known path is served. Slashes
// around the path are ignored, and the path is matched as sent, without
// decoding percent escapes, so there is exactly one spelling of each endpoint
// besides the trailing slash.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.RequestURI
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = "/" + strings.Trim(path, "/")
	rt, found := s.routes[path]
	if !found || r.Method != http.MethodPost {
		write(w, fail(http.StatusNotFound, "not_found"))
		return
	}
	limit := int64(smallBody)
	if rt.large {
		limit = s.maxEnvelopeBody()
	}
	in, err := readInput(r, limit)
	if errors.Is(err, errTooLarge) {
		write(w, fail(http.StatusRequestEntityTooLarge, "too_large"))
		return
	}
	write(w, s.run(rt.handle, r, in))
}

// run calls a handler and turns a panic into a 500, so one bad request cannot
// take the relay down.
func (s *Server) run(h handler, r *http.Request, in input) (res result) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("carrierpony: %s: panic: %v", r.URL.Path, p)
			res = serverError()
		}
	}()
	return h(s, r, in)
}

// serverError is the answer when the relay itself failed. The cause is logged
// by the caller and never sent to the client.
func serverError() result {
	return fail(http.StatusInternalServerError, "server_error")
}

// stamp is the current time as the store keeps it.
func (s *Server) stamp() string {
	return store.Stamp(s.now())
}

// stampIn is the time a number of seconds from now, as the store keeps it.
func (s *Server) stampIn(seconds int) string {
	return store.Stamp(s.now().Add(time.Duration(seconds) * time.Second))
}

// randomHex returns n random bytes as 2n lowercase hex characters.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Package api is the relay's HTTP interface: the same endpoints, status codes
// and JSON the PHP relay answered with.
package api

import (
	"context"
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
	// http makes the relay's outgoing calls, to the push gateway.
	http *http.Client
	// wakes holds one slot per gateway call in flight.
	wakes chan struct{}
}

type handler func(s *Server, ctx context.Context, in input) result

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
	s := &Server{cfg: cfg, store: st, now: time.Now,
		http:  &http.Client{Timeout: 5 * time.Second},
		wakes: make(chan struct{}, maxWakesInFlight)}
	s.routes = map[string]route{
		"/v1/challenge":                 {handle: (*Server).challenge},
		"/v1/register-device":           {handle: (*Server).registerDevice},
		"/v1/send":                      {handle: authed((*Server).send), large: true},
		"/v1/inbox":                     {handle: authed((*Server).inbox)},
		"/v1/ack":                       {handle: authed((*Server).ack)},
		"/v1/register-push":             {handle: authed((*Server).registerPush)},
		"/v1/register-wake":             {handle: authed((*Server).registerWake)},
		"/v1/report":                    {handle: authed((*Server).report)},
		"/v1/pair/offer":                {handle: authed((*Server).pairOffer)},
		"/v1/pair/accept":               {handle: authed((*Server).pairAccept)},
		"/v1/pair/status":               {handle: authed((*Server).pairStatus)},
		"/v1/sealed/register-device":    {handle: (*Server).sealedRegisterDevice},
		"/v1/sealed/register-mailboxes": {handle: (*Server).sealedRegisterMailboxes},
		"/v1/sealed/send":               {handle: (*Server).sealedSend, large: true},
		"/v1/sealed/inbox":              {handle: (*Server).sealedInbox},
		"/v1/sealed/ack":                {handle: (*Server).sealedAck},
	}
	return s
}

// requestContext is the context a request's database work runs under. It is
// cut loose from the connection, so a client that hangs up cannot leave a
// message half stored, and bounded, so nothing waits on the database forever.
func (s *Server) requestContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
}

// stampUnix formats a unix time as the store keeps it.
func stampUnix(seconds int64) string {
	return store.Stamp(time.Unix(seconds, 0))
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
	// The context outlives the handler: a streamed answer still reads from the
	// database while it is being written.
	ctx, cancel := s.requestContext(r)
	defer cancel()
	write(w, s.run(rt.handle, ctx, path, in))
}

// run calls a handler and turns a panic into a 500, so one bad request cannot
// take the relay down.
func (s *Server) run(h handler, ctx context.Context, path string, in input) (res result) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("carrierpony: %s: panic: %v", path, p)
			res = serverError()
		}
	}()
	return h(s, ctx, in)
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

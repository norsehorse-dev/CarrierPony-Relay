// carrierpony-relay is the CarrierPony relay: a store-and-forward server for
// end-to-end encrypted envelopes.
//
//	carrierpony-relay serve -config /etc/carrierpony/config.toml
//	carrierpony-relay version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/api"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const defaultConfig = "/etc/carrierpony/config.toml"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	args := os.Args[1:]
	command := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		command, args = args[0], args[1:]
	}
	switch command {
	case "serve":
		if err := serve(args); err != nil {
			log.Fatalf("carrierpony: %v", err)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\nusage: carrierpony-relay [serve] [-config file] | version\n", command)
		os.Exit(2)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "path of the TOML config file")
	fs.Parse(args)

	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.New(cfg, st),
		ReadHeaderTimeout: 15 * time.Second,
		// Generous enough for the largest envelope over a slow phone link.
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	failed := make(chan error, 1)
	go func() { failed <- srv.ListenAndServe() }()
	log.Printf("carrierpony: relay %s listening on %s, database %s", version, cfg.Listen, st.Driver)

	select {
	case err := <-failed:
		return err
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Printf("carrierpony: relay stopped")
	return nil
}

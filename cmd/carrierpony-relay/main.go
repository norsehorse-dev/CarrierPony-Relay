// carrierpony-relay is the CarrierPony relay: a store-and-forward server for
// end-to-end encrypted envelopes.
//
//	carrierpony-relay serve -config /etc/carrierpony/config.toml
//	carrierpony-relay reap -config /etc/carrierpony/config.toml
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
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/reaper"
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
	case "reap":
		if err := reap(args); err != nil {
			log.Fatalf("carrierpony: %v", err)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\nusage: carrierpony-relay [serve|reap] [-config file] | version\n", command)
		os.Exit(2)
	}
}

// open reads the config named by a command's -config flag and opens its store.
func open(command string, args []string) (config.Config, *store.Store, error) {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	path := fs.String("config", defaultConfig, "path of the TOML config file")
	fs.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil {
		return cfg, nil, err
	}
	st, err := store.Open(cfg.Database)
	return cfg, st, err
}

// reap does one clean-up pass and prints what it removed. It is safe to run
// while the relay is serving.
func reap(args []string) error {
	cfg, st, err := open("reap", args)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	at := time.Now()
	counts, err := reaper.Run(ctx, st, cfg.Limits, at)
	fmt.Println(counts.Line(at))
	return err
}

func serve(args []string) error {
	cfg, st, err := open("serve", args)
	if err != nil {
		return err
	}
	defer st.Close()

	background, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	if cfg.ReapEveryMinutes > 0 {
		go reaper.Every(background, time.Duration(cfg.ReapEveryMinutes)*time.Minute, st, cfg.Limits)
	}

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

// carrierpony-relay is the CarrierPony relay: a store-and-forward server for
// end-to-end encrypted envelopes.
//
//	carrierpony-relay serve -config /etc/carrierpony/config.toml
//	carrierpony-relay reap -config /etc/carrierpony/config.toml
//	carrierpony-relay migrate -config /etc/carrierpony/config.toml
//	carrierpony-relay convert-config -out /etc/carrierpony/config.toml /opt/carrierpony/config.php
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
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/norsehorse-dev/CarrierPony-Relay/internal/api"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/config"
	"github.com/norsehorse-dev/CarrierPony-Relay/internal/convert"
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
	case "migrate":
		if err := migrate(args); err != nil {
			log.Fatalf("carrierpony: %v", err)
		}
	case "convert-config":
		if err := convertConfig(args); err != nil {
			log.Fatalf("carrierpony: %v", err)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\nusage: carrierpony-relay [serve|reap|migrate] [-config file] | convert-config [-out file] config.php | version\n", command)
		os.Exit(2)
	}
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
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

// migrate brings a MySQL database to the layout this relay needs. It is safe to
// run again: each step changes something only when it is missing.
func migrate(args []string) error {
	_, st, err := open("migrate", args)
	if err != nil {
		return err
	}
	defer st.Close()
	if st.Driver != "mysql" {
		fmt.Println("nothing to do: a SQLite database gets its tables when the relay first opens it")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	applied, err := st.Migrate(ctx)
	for _, name := range applied {
		fmt.Println("applied", name)
	}
	if err != nil {
		return err
	}
	return st.CheckSchema(ctx)
}

// convertConfig writes a config.toml from a PHP relay's config.php. PHP itself
// reads the file, since config.php is PHP code, so it needs the php command
// that the relay being replaced already runs on.
func convertConfig(args []string) error {
	fs := flag.NewFlagSet("convert-config", flag.ExitOnError)
	out := fs.String("out", "", "file to write; printed to the terminal when empty")
	php := fs.String("php", "php", "the php command")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: carrierpony-relay convert-config [-out config.toml] /path/to/config.php")
	}
	source := fs.Arg(0)
	if _, err := os.Stat(source); err != nil {
		return err
	}
	raw, err := exec.Command(*php, "-r", "echo json_encode(require $argv[1]);", "--", source).Output()
	if err != nil {
		return fmt.Errorf("could not read %s with %s: %w", source, *php, err)
	}
	cfg, notes, err := convert.FromPHP(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	text, err := convert.Render(cfg, source, notes)
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Print(text)
		return nil
	}
	// The file holds the database password. O_EXCL also keeps a second run
	// from overwriting a config that has since been edited by hand.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	for _, note := range notes {
		fmt.Fprintln(os.Stderr, "note:", note)
	}
	return nil
}

func serve(args []string) error {
	cfg, st, err := open("serve", args)
	if err != nil {
		return err
	}
	defer st.Close()
	checkCtx, cancelCheck := context.WithTimeout(context.Background(), time.Minute)
	err = st.CheckSchema(checkCtx)
	cancelCheck()
	if err != nil {
		return err
	}

	background, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	if cfg.ReapEveryMinutes > 0 {
		go reaper.Every(background, time.Duration(cfg.ReapEveryMinutes)*time.Minute, st, cfg.Limits)
	}

	handler, err := api.New(cfg, st)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
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
	log.Printf("carrierpony: relay %s listening on %s, database %s, own push: apns %s, fcm %s",
		version, cfg.Listen, st.Driver, onOff(cfg.APNs.Enabled), onOff(cfg.FCM.Enabled))

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

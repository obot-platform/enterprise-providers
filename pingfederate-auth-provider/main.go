// Command pingfederate-auth-provider is an Obot authentication provider for
// Ping Identity PingFederate, or any other OpenID Connect provider with a
// standard discovery document. It runs as a daemon next to the Obot server,
// which forwards the browser's OAuth2 traffic to it and asks it who each
// request belongs to.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("ERROR: %s: %v\n", providerName, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadOptions()
	if err != nil {
		return fmt.Errorf("failed to load options: %w", err)
	}
	defer cfg.cleanup()

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}
	listenHost := os.Getenv("OBOT_PROVIDER_LISTEN_HOST")
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	addr := net.JoinHostPort(listenHost, port)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := newServer(ctx, cfg, "http://"+addr)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	fmt.Printf("listening on %s\n", addr)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to listen and serve: %w", err)
	}
	return nil
}

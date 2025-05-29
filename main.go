package main

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/lehigh-university-libraries/antibot/pkg/antibot"
	"sigs.k8s.io/yaml"
)

type Config struct {
	Backend string         `json:"backend-url"`
	AntiBot antibot.Config `json:"config"`
}

func main() {
	data, err := os.ReadFile("antibot.yaml")
	if err != nil {
		slog.Error("Could not read antibot.yaml", "err", err)
		os.Exit(1)
	}

	expanded := os.ExpandEnv(string(data))
	slog.Info("exp", "e", expanded)
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		slog.Error("Could not parse antibot.yaml", "err", err)
		os.Exit(1)
	}

	targetURL, err := url.Parse(cfg.Backend)
	if err != nil {
		slog.Error("Could not parse backend URL", "err", err)
		os.Exit(1)
	}

	slog.Info("CONFIG", "config", cfg)
	s := NewServer()
	ab, err := antibot.NewAntiBot(&cfg.AntiBot)
	if err != nil {
		slog.Error("Could not load antibot config", "err", err)
		os.Exit(1)
	}
	s.Use(ab.Middleware)

	// do not add middleware to healthcheck to avoid verbose logging
	s.HandleNoMiddleware("/healthcheck", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("OK"))
		if err != nil {
			slog.Error("Unable to write healthcheck", "err", err)
			os.Exit(1)
		}
	}))

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}))

	slog.Info("Server is starting :8888")
	if err := s.ListenAndServe(":8888"); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)
	}
}

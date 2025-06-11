package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	antibot "github.com/lehigh-university-libraries/antibot/config"
	"sigs.k8s.io/yaml"
)

func main() {
	level := getLogLevel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	data, err := os.ReadFile("antibot.yaml")
	if err != nil {
		slog.Error("Could not read antibot.yaml", "err", err)
		os.Exit(1)
	}

	expanded := os.ExpandEnv(string(data))
	var cfg antibot.Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		slog.Error("Could not parse antibot.yaml", "err", err)
		os.Exit(1)
	}

	s := NewServer()
	ab, err := antibot.NewAntiBot(&cfg)
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

	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			slog.Error("Unable to write response", "err", err)
			os.Exit(1)
		}
	}))

	slog.Info("Server is starting :8888")
	if err := s.ListenAndServe(":8888"); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)
	}
}

func getLogLevel() slog.Level {
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

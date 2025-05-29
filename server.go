package main

import (
	"log/slog"
	"net/http"
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		statusWriter := &statusRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(statusWriter, r)
		duration := time.Since(start)
		slog.Info(r.Method,
			"path", r.URL.Path,
			"status", statusWriter.statusCode,
			"duration", duration,
			"client_ip", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

type Middleware func(http.Handler) http.Handler

type Server struct {
	mux         *http.ServeMux
	middlewares []Middleware
}

func NewServer() *Server {
	return &Server{
		mux:         http.NewServeMux(),
		middlewares: []Middleware{},
	}
}

func (s *Server) Use(mw Middleware) {
	s.middlewares = append(s.middlewares, mw)
}

func (s *Server) Handle(pattern string, handler http.Handler) {
	finalHandler := handler
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		finalHandler = s.middlewares[i](finalHandler)
	}
	s.mux.Handle(pattern, finalHandler)
}

func (s *Server) HandleNoMiddleware(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, handler)
}

func (a *Server) ListenAndServe(address string) error {
	return http.ListenAndServe(address, a.mux)
}

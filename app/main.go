package main

import (
	"fmt"
	"net/http"
	"strings"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	Addr   string `yaml:"addr"`
	Secret string `yaml:"secret"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := yaml.Unmarshal(file, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

type Handler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

type Middleware interface {
	Protect(next Handler) http.Handler
}

type HomeHandler struct {
	Logger *zap.Logger
}

func (h *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("Home endpoint accessed")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Welcome to the Go HTTP Service!"))
}

type HealthHandler struct {
	Logger *zap.Logger
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("Health check accessed")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

type JWTMiddleware struct {
	Logger *zap.Logger
	Secret string
}

func (m *JWTMiddleware) Protect(next Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tokenString == "" {
			m.Logger.Warn("Unauthorized access attempt")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(m.Secret), nil
		}, jwt.WithValidMethods([]string{"HS256"}))
		if err != nil {
			m.Logger.Warn("Invalid JWT token", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		m.Logger.Info("Valid JWT token received")
		next.ServeHTTP(w, r)
	})
}

type HTTPServer struct {
	Config         *Config
	Mux            *http.ServeMux
	Logger         *zap.Logger
	Handlers       map[string]Handler
	AuthMiddleware Middleware
}

func NewHTTPServer(config *Config) *HTTPServer {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	handlers := map[string]Handler{
		"/":       &HomeHandler{Logger: logger},
		"/health": &HealthHandler{Logger: logger},
	}
	authMiddleware := &JWTMiddleware{Logger: logger, Secret: config.Secret}

	httpServer := &HTTPServer{
		Config:         config,
		Mux:            http.NewServeMux(),
		Logger:         logger,
		Handlers:       handlers,
		AuthMiddleware: authMiddleware,
	}

	httpServer.Mux.Handle("/", httpServer.AuthMiddleware.Protect(httpServer.Handlers["/"]))
	httpServer.Mux.Handle("/health", httpServer.Handlers["/health"])

	return httpServer
}

func (s *HTTPServer) Start() {
	s.Logger.Info("Starting server", zap.String("address", s.Config.Addr))
	if err := http.ListenAndServe(s.Config.Addr, s.Mux); err != nil {
		s.Logger.Fatal("Server failed to start", zap.Error(err))
	}
}

func main() {
	config, err := LoadConfig("config.yaml")
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	server := NewHTTPServer(config)
	server.Start()
}
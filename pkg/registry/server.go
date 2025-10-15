package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/registries/python"
	"github.com/flemse/oci-package-proxy/pkg/registries/terraform"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Server represents the registry server
type Server struct {
	config     *config.ServerConfig
	httpServer *http.Server
	router     chi.Router
}

// NewServer creates a new registry server with the given configuration
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	// Load package list if not provided
	packageList := cfg.PackageList
	if packageList == nil && cfg.PackageConfigFile != "" {
		var err error
		packageList, err = config.LoadPackageConfig(cfg.PackageConfigFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load package config: %w", err)
		}
	}
	if packageList == nil {
		return nil, fmt.Errorf("package list must be provided either via PackageList or PackageConfigFile")
	}

	// Create router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Setup host configuration
	hostCfg := &config.HostConfig{
		Host:          cfg.HostOCI,
		AllowInsecure: cfg.AllowInsecureOCI,
		OrgKey:        cfg.OrgName,
	}

	// Setup Terraform registry
	tfReg := terraform.NewRegistry(hostCfg, packageList)
	tfReg.SetupRoutes(r)

	// Setup Python registry
	pyReg := python.NewRegistry(hostCfg, packageList)
	pyReg.SetupRoutes(r)

	return &Server{
		config: cfg,
		router: r,
	}, nil
}

// Start starts the registry server
func (s *Server) Start() error {
	addr := net.JoinHostPort("", s.config.Port)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Registry Server starting on %s", addr)

	if s.config.SkipTLS {
		return s.httpServer.ListenAndServe()
	}

	// Use provided TLS certificate or load from files
	if s.config.TLSCert != nil {
		s.httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*s.config.TLSCert},
		}
		return s.httpServer.ListenAndServeTLS("", "")
	}

	return s.httpServer.ListenAndServeTLS(s.config.CertFilePath, s.config.KeyFilePath)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Router returns the underlying chi router for testing purposes
func (s *Server) Router() chi.Router {
	return s.router
}

// Addr returns the server address (only available after Start is called)
func (s *Server) Addr() string {
	if s.httpServer != nil {
		return s.httpServer.Addr
	}
	return net.JoinHostPort("", s.config.Port)
}

package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/flemse/oci-package-proxy/internal/devcert"
	"github.com/flemse/oci-package-proxy/pkg/registries/terraform"
	"github.com/flemse/oci-package-proxy/pkg/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

var (
	port             string
	hostOCI          string
	allowInsecureOCI bool
	repoName         string
)

// registryCmd represents the registry command
var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "terraform registry",
	Long:  `terraform registry host`,
	Run: func(cmd *cobra.Command, args []string) {
		devcert.GenerateCert()

		r := chi.NewRouter()
		r.Use(middleware.RequestID)
		r.Use(middleware.Logger)

		repo, err := NewRepository(fmt.Sprintf("%s/%s", hostOCI, repoName))
		if err != nil {
			log.Fatalf("failed to create repository: %v", err)
		}

		repo.PlainHTTP = allowInsecureOCI
		reg := terraform.Registry{
			OCI: store.NewStore(repo),
		}
		reg.SetupRoutes(r)

		addr := net.JoinHostPort("", port)
		log.Printf("Terraform Registry Server running on %s", addr)
		log.Fatal(http.ListenAndServeTLS(addr, "tmp/cert.pem", "tmp/key.pem", r))
	},
}

func init() {
	rootCmd.AddCommand(registryCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	registryCmd.PersistentFlags().StringVarP(&port, "port", "p", "8080", "port to run the server")
	registryCmd.PersistentFlags().StringVar(&hostOCI, "oci-host", "ghcr.io", "host for the OCI registry eq. ghcr.io or localhost:5001")
	registryCmd.PersistentFlags().BoolVar(&allowInsecureOCI, "oci-insecure", false, "allow insecure connections to the OCI registry")
	registryCmd.PersistentFlags().StringVar(&repoName, "repo-name", "novus/applicationmanagement", "repository name for the OCI registry")
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// registryCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func NewRepository(reference string) (*remote.Repository, error) {
	token := os.Getenv("GITHUB_TOKEN")
	repo, err := remote.NewRepository(reference)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}
	if token == "" {
		return repo, nil
	}

	c := auth.DefaultClient
	c.Credential = func(ctx context.Context, registry string) (auth.Credential, error) {
		return auth.Credential{
			Username: "oauth2", // GitHub requires "oauth2" as the username for PATs
			Password: token,
		}, nil
	}

	repo.Client = c
	return repo, nil
}

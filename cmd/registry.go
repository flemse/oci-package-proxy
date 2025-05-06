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

// registryCmd represents the registry command
var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "terraform registry",
	Long:  `terraform registry host`,
	Run: func(cmd *cobra.Command, args []string) {
		port, err := cmd.Flags().GetString("port")
		if err != nil {
			log.Fatal("failed to get port flag", err)
		}

		devcert.GenerateCert()

		r := chi.NewRouter()
		r.Use(middleware.RequestID)
		r.Use(middleware.Logger)

		host := "ghcr.io"
		repoName := "lego/novus/applicationmanagement"
		repo, err := setupRepoClientWithAuth(fmt.Sprintf("%s/%s", host, repoName))
		//repo.PlainHTTP = true

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
	registryCmd.PersistentFlags().StringP("port", "p", "8080", "port to run the server")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// registryCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func setupRepoClientWithAuth(repoURL string) (*remote.Repository, error) {
	// Get the GitHub token from the environment
	token := getGitHubToken()

	// Create the repository client
	repo, err := remote.NewRepository(repoURL)
	if err != nil {
		return nil, err
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

func getGitHubToken() string {
	token := os.Getenv("GITHUB_TOKEN")
	return token
}

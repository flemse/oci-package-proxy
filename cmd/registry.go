package cmd

import (
	"log"
	"net"
	"net/http"

	"github.com/flemse/oci-package-proxy/internal/devcert"
	"github.com/flemse/oci-package-proxy/pkg/registries/terraform"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
)

var (
	port              string
	hostOCI           string
	orgName           string
	allowInsecureOCI  bool
	packageConfigFile string
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

		packageList, err := terraform.LoadPackageConfig(packageConfigFile)
		if err != nil {
			log.Fatalf("failed to load package config: %v", err)
		}

		reg := terraform.NewRegistry(hostOCI, orgName, allowInsecureOCI, packageList)
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
	registryCmd.PersistentFlags().StringVar(&orgName, "org-name", "lego", "organization name for the OCI registry")
	registryCmd.PersistentFlags().BoolVar(&allowInsecureOCI, "oci-insecure", false, "allow insecure connections to the OCI registry")
	registryCmd.PersistentFlags().StringVar(&packageConfigFile, "package-config", "tmp/packages.yaml", "path to the package config file")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// registryCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

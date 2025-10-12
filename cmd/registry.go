package cmd

import (
	"log"
	"net"
	"net/http"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/registries/python"
	"github.com/flemse/oci-package-proxy/pkg/registries/terraform"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
)

var (
	port              string
	skipTLS           bool
	certFilePath      string
	keyFilePath       string
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
		r := chi.NewRouter()
		r.Use(middleware.RequestID)
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)

		packageList, err := config.LoadPackageConfig(packageConfigFile)
		if err != nil {
			log.Fatalf("failed to load package config: %v", err)
		}
		hostCfg := &config.HostConfig{
			Host:          hostOCI,
			AllowInsecure: allowInsecureOCI,
			OrgKey:        orgName,
		}

		reg := terraform.NewRegistry(hostCfg, packageList)
		reg.SetupRoutes(r)

		pyReg := python.NewRegistry(hostCfg, packageList)
		pyReg.SetupRoutes(r)

		addr := net.JoinHostPort("", port)
		log.Printf("Terraform Registry Server running on %s", addr)
		if skipTLS {
			log.Fatal(http.ListenAndServe(addr, r))
		}

		log.Fatal(http.ListenAndServeTLS(addr, certFilePath, keyFilePath, r))
	},
}

func init() {
	rootCmd.AddCommand(registryCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:

	registryCmd.PersistentFlags().StringVarP(&port, "port", "p", "8080", "port to run the server")
	registryCmd.PersistentFlags().BoolVar(&skipTLS, "skip-tls", false, "skip TLS")
	registryCmd.PersistentFlags().StringVar(&certFilePath, "cert-file", "tmp/cert.pem", "path to the TLS certificate file")
	registryCmd.PersistentFlags().StringVar(&keyFilePath, "key-file", "tmp/key.pem", "path to the TLS key file")
	registryCmd.PersistentFlags().StringVar(&hostOCI, "oci-host", "ghcr.io", "host for the OCI registry eq. ghcr.io or localhost:5001")
	registryCmd.PersistentFlags().StringVar(&orgName, "org-name", "lego", "organization name for the OCI registry")
	registryCmd.PersistentFlags().BoolVar(&allowInsecureOCI, "oci-insecure", false, "allow insecure connections to the OCI registry")
	registryCmd.PersistentFlags().StringVar(&packageConfigFile, "package-config", "tmp/packages.yaml", "path to the package config file")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// registryCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

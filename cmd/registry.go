package cmd

import (
	"log"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/registry"
	"github.com/spf13/cobra"
)

var cfg config.ServerConfig

// registryCmd represents the registry command
var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "terraform registry",
	Long:  `terraform registry host`,
	Run: func(cmd *cobra.Command, args []string) {
		server, err := registry.NewServer(&cfg)
		if err != nil {
			log.Fatalf("failed to create server: %v", err)
		}

		if err := server.Start(); err != nil {
			log.Fatalf("failed to start server: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(registryCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:

	registryCmd.PersistentFlags().StringVarP(&cfg.Port, "port", "p", "8080", "port to run the server")
	registryCmd.PersistentFlags().BoolVar(&cfg.SkipTLS, "skip-tls", false, "skip TLS")
	registryCmd.PersistentFlags().StringVar(&cfg.CertFilePath, "cert-file", "tmp/cert.pem", "path to the TLS certificate file")
	registryCmd.PersistentFlags().StringVar(&cfg.KeyFilePath, "key-file", "tmp/key.pem", "path to the TLS key file")
	registryCmd.PersistentFlags().StringVar(&cfg.HostOCI, "oci-host", "ghcr.io", "host for the OCI registry eq. ghcr.io or localhost:5001")
	registryCmd.PersistentFlags().StringVar(&cfg.OrgName, "org-name", "lego", "organization name for the OCI registry")
	registryCmd.PersistentFlags().BoolVar(&cfg.AllowInsecureOCI, "oci-insecure", false, "allow insecure connections to the OCI registry")
	registryCmd.PersistentFlags().StringVar(&cfg.PackageConfigFile, "package-config", "tmp/packages.yaml", "path to the package config file")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// registryCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

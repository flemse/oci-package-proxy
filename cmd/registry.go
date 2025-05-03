package cmd

import (
	"log"
	"net"
	"net/http"

	"fth-test-app/internal/devcert"
	"fth-test-app/pkg/registries/terraform"
	"github.com/spf13/cobra"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
		terraform.SetupRoutes(r)

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

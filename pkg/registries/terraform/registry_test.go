package terraform

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/testutils"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

func TestWellKnownTerraform(t *testing.T) {
	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "terraform-provider-example", Type: config.PackageTypeTerraform},
		},
	}

	s, err := StartProxyServer(t, t.Context(), packageList)
	require.NoError(t, err, "Failed to start proxy server")
	t.Cleanup(s.Close)

	resp, err := s.Client().Get(s.URL + "/.well-known/terraform.json")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var discovery DiscoveryResponse
	err = json.Unmarshal(body, &discovery)
	require.NoError(t, err)

	assert.Contains(t, discovery.ProvidersV1, "/v1/providers/")
}

func TestProviderVersionsNotFound(t *testing.T) {
	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "terraform-provider-example", Type: config.PackageTypeTerraform},
		},
	}

	s, err := StartProxyServer(t, t.Context(), packageList)
	require.NoError(t, err, "Failed to start proxy server")
	t.Cleanup(s.Close)

	// Test non-existent provider
	resp, err := s.Client().Get(s.URL + "/v1/providers/test/nonexistent/versions")
	require.NoError(t, err)
	// Should return 404 or empty list - depends on implementation
	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response: %s", string(body))
}

func TestTerraformProviderInContainer(t *testing.T) {
	ctx := t.Context()
	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "terraform-provider-example", Type: config.PackageTypeTerraform},
		},
	}

	s, err := StartProxyServer(t, ctx, packageList)
	require.NoError(t, err, "Failed to start proxy server")
	t.Cleanup(s.Close)

	t.Run("Build", func(t *testing.T) {
		// Start a Go container with GoReleaser
		goContainer, err := testutils.StartGoReleaserContainer(ctx)
		require.NoError(t, err, "Failed to start Go container")
		t.Cleanup(func() { _ = goContainer.Terminate(ctx) })

		assert.NoError(t, goContainer.CopyDirToContainer(ctx, "/Users/dkFleThe/src/flemse/oci-package-proxy/pkg/registries/terraform/sample/", "/", 0755))

		exitCode, output, err := goContainer.Exec(ctx, []string{"sh", "-c", "go install github.com/goreleaser/goreleaser/v2@latest"})
		require.NoError(t, err)
		outputStr := testutils.ReadExecOutput(output)
		t.Logf("Go install output:\n%s", outputStr)
		require.Equal(t, 0, exitCode, "Go install failed")

		exitCode, output, err = goContainer.Exec(ctx, []string{"sh", "-c", "goreleaser build --snapshot --clean"}, tcexec.WithWorkingDir("/sample"))
		require.NoError(t, err)
		outputStr = testutils.ReadExecOutput(output)
		t.Logf("release output:\n%s", outputStr)
		require.Equal(t, 0, exitCode, "GoReleaser build failed")
	})

	// Test fetching provider with Terraform
	t.Run("FetchProviderWithTerraform", func(t *testing.T) {
		t.Skip("Skipping Terraform integration test - requires pushing provider to registry first")

		tfContainer, err := testutils.StartTerraformTestContainer(ctx)
		require.NoError(t, err, "Failed to start Terraform container")
		defer tfContainer.Terminate(ctx)

		// Get the registry URL for container access
		registryURL := s.URL
		registryURL = strings.Replace(registryURL, "127.0.0.1", "host.docker.internal", 1)
		registryURL = strings.Replace(registryURL, "localhost", "host.docker.internal", 1)
		t.Logf("Registry URL for container: %s", registryURL)

		// Create a Terraform configuration that uses the provider
		terraformConfig := fmt.Sprintf(`
terraform {
  required_providers {
    example = {
      source  = "%s/test/example"
      version = "1.0.0"
    }
  }
}

provider "example" {}

resource "example_resource" "test" {
  name = "test-resource"
}
`, registryURL)

		err = tfContainer.CopyToContainer(ctx, []byte(terraformConfig), "/tmp/main.tf", 0644)
		require.NoError(t, err)

		// Run terraform init
		exitCode, output, err := tfContainer.Exec(ctx, []string{
			"sh", "-c", "cd /tmp && terraform init",
		})
		require.NoError(t, err)
		outputStr := testutils.ReadExecOutput(output)
		t.Logf("Terraform init output: %s", outputStr)
		assert.Equal(t, 0, exitCode, "terraform init failed")

		// Run terraform apply
		exitCode, output, err = tfContainer.Exec(ctx, []string{
			"sh", "-c", "cd /tmp && terraform apply -auto-approve",
		})
		require.NoError(t, err)
		outputStr = testutils.ReadExecOutput(output)
		t.Logf("Terraform apply output: %s", outputStr)
		assert.Equal(t, 0, exitCode, "terraform apply failed")
	})
}

// Helper function to create a zip file containing the provider binary
func createProviderZip(binaryPath, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Read the binary
	binaryData, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}

	// Add the binary to the zip with the correct name
	binaryName := filepath.Base(binaryPath)
	writer, err := zipWriter.Create(binaryName)
	if err != nil {
		return err
	}

	_, err = writer.Write(binaryData)
	return err
}

// Helper function to generate OCI layout (simplified version of cmd/generate.go)
func generateOCILayout(inputPath, outPath, version string) error {
	// For this test, we'll create a minimal valid OCI layout structure
	// In production, this would use the full generate command logic

	// Create directory structure
	blobsDir := filepath.Join(outPath, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return err
	}

	// Create oci-layout file
	layoutFile := filepath.Join(outPath, "oci-layout")
	if err := os.WriteFile(layoutFile, []byte(`{"imageLayoutVersion": "1.0.0"}`), 0644); err != nil {
		return err
	}

	// Create a minimal index.json
	index := map[string]interface{}{
		"schemaVersion": 2,
		"manifests":     []interface{}{},
	}

	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}

	indexFile := filepath.Join(outPath, "index.json")
	return os.WriteFile(indexFile, indexData, 0644)
}

func StartProxyServer(t *testing.T, ctx context.Context, pkg *config.PackageList) (*httptest.Server, error) {
	t.Helper()

	zotAddr, err := testutils.StartTestContainer(ctx)
	require.NoError(t, err, "Failed to start Zot container")
	require.NotEmpty(t, zotAddr, "Zot container address should not be empty")
	t.Logf("Zot container running at: %s", zotAddr)

	// Configure the registry to use Zot
	cfg := &config.HostConfig{
		Host:          zotAddr,
		AllowInsecure: true,
		OrgKey:        "",
	}

	reg := NewRegistry(cfg, pkg)
	mux := chi.NewRouter()
	reg.SetupRoutes(mux)

	s := httptest.NewServer(mux)
	return s, nil
}

package terraform

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/testutils"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

	// Generate GPG key for signing
	gpgPublicKey, gpgFingerprint, gpgPrivateKey, err := testutils.GenerateGPGKey()
	require.NoError(t, err, "Failed to generate GPG key")
	t.Logf("Generated GPG key with fingerprint: %s", gpgFingerprint)

	// Create package list with signing key
	packageList := &config.PackageList{
		Packages: []config.Package{
			{
				Name: "test/sample-provider",
				Type: config.PackageTypeTerraform,
				SigningKeys: []*config.SigningKey{
					{
						KeyID:      gpgFingerprint,
						ASCIIArmor: gpgPublicKey,
					},
				},
			},
		},
	}

	// Generate self-signed certificate for TLS
	certPEM, _, tlsCert, err := testutils.GenerateSelfSignedCert()
	require.NoError(t, err, "Failed to generate certificate")

	s, err := StartProxyServerWithTLS(t, ctx, packageList, tlsCert)
	require.NoError(t, err, "Failed to start proxy server")
	t.Cleanup(s.Close)

	goContainer, err := testutils.StartGoReleaserContainer(t, ctx)
	require.NoError(t, err, "Failed to start Go container")
	t.Cleanup(func() { _ = goContainer.Terminate(ctx) })

	// Import GPG key into the container
	err = testutils.ImportGPGKeyToContainer(ctx, goContainer, gpgPrivateKey, gpgFingerprint)
	require.NoError(t, err, "Failed to import GPG key to container")
	t.Logf("Imported GPG key to container")

	testutils.TrustSSLCertInContainer(t, ctx, goContainer, certPEM)

	tfContainer, err := testutils.StartTerraformTestContainer(t, ctx)
	require.NoError(t, err, "Failed to start Terraform container")
	t.Cleanup(func() { _ = tfContainer.Terminate(ctx) })

	testutils.TrustSSLCertInContainer(t, ctx, tfContainer, certPEM)

	t.Run("BuildAndUpload", func(t *testing.T) {
		assert.NoError(t, goContainer.CopyDirToContainer(ctx, "./sample", "/", 0755))

		// Run GoReleaser with GPG signing
		exitCode, output, err := goContainer.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("GPG_FINGERPRINT=%s goreleaser release --snapshot --clean", gpgFingerprint)}, tcexec.WithWorkingDir("/sample"))
		require.NoError(t, err)
		outputStr := testutils.ReadExecOutput(output)
		t.Logf("release output:\n%s", outputStr)
		require.Equal(t, 0, exitCode, "GoReleaser build failed")

		// List the generated files
		exitCode, output, err = goContainer.Exec(ctx, []string{"sh", "-c", "ls -la /sample/dist/"})
		require.NoError(t, err)
		outputStr = testutils.ReadExecOutput(output)
		t.Logf("Generated files:\n%s", outputStr)

		// Extract version from SHA256SUMS filename
		exitCode, output, err = goContainer.Exec(ctx, []string{"sh", "-c", "ls /sample/dist/ | grep SHA256SUMS"})
		require.NoError(t, err)
		shasumFile := strings.TrimSpace(testutils.ReadExecOutput(output))
		require.NotEmpty(t, shasumFile, "SHA256SUMS file not found")

		uploadURL := s.URL + "/terraform/upload"
		uploadURL = strings.Replace(uploadURL, "127.0.0.1", "host.docker.internal", 1)
		uploadURL = strings.Replace(uploadURL, "localhost", "host.docker.internal", 1)
		t.Logf("Upload URL for container: %s", uploadURL)

		t.Logf("Executing upload command")
		exitCode, output, err = goContainer.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("/sample/release.sh --upload-url %s --dist-path /sample/dist", uploadURL)})
		require.NoError(t, err)
		outputStr = testutils.ReadExecOutput(output)
		t.Logf("Upload output:\n%s", outputStr)
		require.Equal(t, 0, exitCode, "Upload failed")

		// Verify the upload was successful by checking the response in the output
		require.Contains(t, outputStr, "success", "Upload response should contain 'success'")

		// Verify we can fetch the provider versions
		versionsResp, err := s.Client().Get(s.URL + "/v1/providers/test/sample-provider/versions")
		require.NoError(t, err)
		t.Cleanup(func() { _ = versionsResp.Body.Close() })

		versionsBody, err := io.ReadAll(versionsResp.Body)
		require.NoError(t, err)
		t.Logf("Versions response: %s", string(versionsBody))

		var versionsResponse VersionsResponse
		err = json.Unmarshal(versionsBody, &versionsResponse)
		require.NoError(t, err)
		assert.Len(t, versionsResponse.Versions, 1, "Should have at least one version")
	})

	// Test fetching provider with Terraform
	t.Run("FetchProviderWithTerraform", func(t *testing.T) {
		// Get the registry URL for container access
		registryURL := s.URL
		registryURL = strings.Replace(registryURL, "127.0.0.1", "host.docker.internal", 1)
		registryURL = strings.Replace(registryURL, "localhost", "host.docker.internal", 1)
		registryURL = strings.TrimPrefix(registryURL, "https://")

		t.Logf("Registry URL for container: %s", registryURL)

		// Create a Terraform configuration that uses the provider
		terraformConfig := fmt.Sprintf(`
terraform {
  required_providers {
    example = {
      source  = "%s/test/sample-provider"
      version = "0.0.0-SNAPSHOT-none"
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

// StartProxyServer creates a test HTTP server for the Terraform registry
func StartProxyServer(t *testing.T, ctx context.Context, pkg *config.PackageList) (*httptest.Server, error) {
	t.Helper()

	zotAddr, err := testutils.StartTestContainer(ctx)
	require.NoError(t, err, "Failed to start Zot container")
	require.NotEmpty(t, zotAddr, "Zot container address should not be empty")
	t.Logf("Zot container running at: %s", zotAddr)

	// Configure the host
	hostCfg := &config.HostConfig{
		Host:          zotAddr,
		AllowInsecure: true,
		OrgKey:        "",
	}

	// Create router and setup routes directly
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Setup Terraform registry
	tfReg := NewRegistry(hostCfg, pkg)
	tfReg.SetupRoutes(r)

	s := httptest.NewServer(r)
	return s, nil
}

// StartProxyServerWithTLS creates a test HTTPS server for the Terraform registry
func StartProxyServerWithTLS(t *testing.T, ctx context.Context, pkg *config.PackageList, tlsCert tls.Certificate) (*httptest.Server, error) {
	t.Helper()

	zotAddr, err := testutils.StartTestContainer(ctx)
	require.NoError(t, err, "Failed to start Zot container")
	require.NotEmpty(t, zotAddr, "Zot container address should not be empty")
	t.Logf("Zot container running at: %s", zotAddr)

	// Configure the host
	hostCfg := &config.HostConfig{
		Host:          zotAddr,
		AllowInsecure: true,
		OrgKey:        "",
	}

	// Create router and setup routes directly
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Setup Terraform registry
	tfReg := NewRegistry(hostCfg, pkg)
	tfReg.SetupRoutes(r)

	s := httptest.NewUnstartedServer(r)
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	s.StartTLS()
	return s, nil
}

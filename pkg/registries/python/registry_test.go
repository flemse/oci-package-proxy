package python

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/testutils"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestHandleSimpleIndex(t *testing.T) {
	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "example", Type: config.PackageTypePython},
			{Name: "another-package", Type: config.PackageTypePython},
			{Name: "terraform-provider-aws", Type: config.PackageTypeTerraform}, // Should not appear
		},
	}

	s, err := StartProxyServer(t, t.Context(), packageList)
	t.Cleanup(s.Close)

	c := s.Client()
	resp, err := c.Get(s.URL + "/simple/")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	bodyStr := string(body)

	// Should include Python packages
	if !strings.Contains(bodyStr, "example") {
		t.Errorf("index missing 'example' package")
	}
	if !strings.Contains(bodyStr, "another-package") {
		t.Errorf("index missing 'another-package' package")
	}

	// Should NOT include non-Python packages
	if strings.Contains(bodyStr, "terraform-provider-aws") {
		t.Errorf("index should not include Terraform packages")
	}
}

func TestHandlePackageUpload_AuthForward(t *testing.T) {
	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "example", Type: config.PackageTypePython},
		},
	}

	s, err := StartProxyServer(t, t.Context(), packageList)
	assert.NoError(t, err, "Failed to start proxy server")
	t.Cleanup(s.Close)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "example-0.1.0.tar.gz")
	_, err = fw.Write([]byte("dummy python package content"))
	assert.NoError(t, err)
	assert.NoError(t, mw.WriteField("name", "example"))
	assert.NoError(t, mw.WriteField("version", "0.1.0"))
	assert.NoError(t, mw.Close())

	r, err := http.NewRequest(http.MethodPost, s.URL+"/upload/", &buf)
	assert.NoError(t, err)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := s.Client().Do(r)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	bd, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "OK", string(bd))
}

func TestPythonPackageInContainer(t *testing.T) {
	ctx := t.Context()
	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "test-package", Type: config.PackageTypePython},
		},
	}
	s, err := StartProxyServer(t, ctx, packageList)
	assert.NoError(t, err, "Failed to start proxy server")
	t.Cleanup(s.Close)

	pythonContainer, err := testutils.StartPythonTestContainer(ctx)
	assert.NoError(t, err, "Failed to start Python container")
	t.Cleanup(func() { _ = pythonContainer.Terminate(ctx) })

	uploadURL := s.URL + "/upload/"

	// Since containers can't reach localhost, we need to use host.docker.internal or the host IP
	uploadURL = strings.Replace(uploadURL, "127.0.0.1", "host.docker.internal", 1)
	uploadURL = strings.Replace(uploadURL, "localhost", "host.docker.internal", 1)

	mainContent := `def hello_world():
    return "Hello from test package!"`
	err = pythonContainer.CopyToContainer(ctx, []byte(mainContent), "/tmp/producer/test_package/__init__.py", 0644)
	assert.NoError(t, err)

	pyproject := `[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "test-package"
version = "0.1.0"
description = "A test package for integration testing"
requires-python = ">=3.6"

[project.optional-dependencies]
dev = ["build", "twine"]

[tool.setuptools]
packages = ["test_package"]`
	err = pythonContainer.CopyToContainer(ctx, []byte(pyproject), "/tmp/producer/pyproject.toml", 0644)
	assert.NoError(t, err)

	pypirc := fmt.Sprintf(`[distutils]
index-servers =
	oci-package-proxy

[oci-package-proxy]
repository: %s
username: user
password: password`, uploadURL)

	err = pythonContainer.CopyToContainer(ctx, []byte(pypirc), "/root/.pypirc", 0644)
	assert.NoError(t, err, "Failed to copy .pypirc to container")

	// Create a simple Python package structure inside the container
	packageSetup := []struct {
		name    string
		command []string
	}{
		{
			name:    "Install build tools and twine",
			command: []string{"pip", "install", "--quiet", "build", "twine"},
		},
		{
			name:    "Build the package",
			command: []string{"sh", "-c", "cd /tmp/producer && python -m build"},
		},
	}

	// Execute all setup commands
	for _, step := range packageSetup {
		t.Logf("Executing: %s", step.name)
		exitCode, output, err := pythonContainer.Exec(ctx, step.command)
		assert.NoError(t, err, "Failed to exec command: %s", step.name)

		// Read output
		outputStr := testutils.ReadExecOutput(output)

		if exitCode != 0 {
			t.Logf("Command output: %s", outputStr)
		}
		assert.Equal(t, 0, exitCode, "Command failed: %s\nOutput: %s", step.name, outputStr)
	}

	t.Run("PushPackage", func(t *testing.T) {
		exitCode, output, err := pythonContainer.Exec(ctx, []string{
			"sh", "-c", "cd /tmp/producer && twine upload --repository oci-package-proxy dist/test_package-0.1.0-py3-none-any.whl",
		})
		assert.NoError(t, err, "Failed to upload package")

		outputStr := testutils.ReadExecOutput(output)
		t.Logf("Upload output: %s", outputStr)

		// Twine returns 0 on success
		assert.Equal(t, 0, exitCode, "Twine upload failed with exit code %d\nOutput: %s", exitCode, outputStr)
	})

	t.Run("InstallPackage", func(t *testing.T) {
		installContainer, err := testutils.StartPythonTestContainer(ctx)
		assert.NoError(t, err, "Failed to start installation container")
		defer installContainer.Terminate(ctx)

		// Get the simple index URL for pip to use
		simpleIndexURL := s.URL + "/simple"
		// Fix URL for container access
		simpleIndexURL = strings.Replace(simpleIndexURL, "127.0.0.1", "host.docker.internal", 1)
		simpleIndexURL = strings.Replace(simpleIndexURL, "localhost", "host.docker.internal", 1)
		t.Logf("Simple index URL for container: %s", simpleIndexURL)

		pyproject := `[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "consumer"
version = "0.1.0"
description = "A consumer package that depends on test-package"
requires-python = ">=3.6"
dependencies = [
    "test-package==0.1.0",
]
`
		err = installContainer.CopyToContainer(ctx, []byte(pyproject), "/tmp/consumer/pyproject.toml", 0644)
		assert.NoError(t, err, "Failed to copy consumer pyproject.toml to container")

		exitCode, output, err := installContainer.Exec(ctx, []string{
			"sh", "-c", fmt.Sprintf("cd /tmp/consumer && pip install --extra-index-url %s --trusted-host host.docker.internal --quiet .", simpleIndexURL),
		})
		assert.NoError(t, err, "Failed to install consumer package")
		outputStr := testutils.ReadExecOutput(output)
		t.Logf("Installation output: %s", outputStr)

		if exitCode != 0 {
			t.Fatalf("Failed to install consumer package with exit code %d\nOutput: %s", exitCode, outputStr)
		}

		// Test that both packages work correctly
		exitCode, output, err = installContainer.Exec(ctx, []string{
			"sh", "-c", "cd /tmp/consumer && python -c \"from test_package import hello_world; print(hello_world())\"",
		})
		assert.NoError(t, err, "Failed to test installed package")
		outputStr = testutils.ReadExecOutput(output)
		t.Logf("Test output: %s", outputStr)
		assert.Equal(t, 0, exitCode, "Failed to run test")
		assert.Contains(t, outputStr, "Hello from test package!", "Package function did not work as expected")

		t.Log("Successfully installed and tested package from OCI registry via pip!")
	})
}

func StartProxyServer(t *testing.T, ctx context.Context, pkg *config.PackageList) (*httptest.Server, error) {
	t.Helper()

	zotAddr, err := testutils.StartTestContainer(ctx)
	assert.NoError(t, err, "Failed to start Zot container")
	assert.NotEmpty(t, zotAddr, "Zot container address should not be empty")
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

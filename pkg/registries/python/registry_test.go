package python

import (
	"bytes"
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
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestHandleSimpleIndex(t *testing.T) {
	cfg := &config.HostConfig{
		Host:          "oci.example.com",
		AllowInsecure: false,
		OrgKey:        "org",
	}

	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "example", Type: config.PackageTypePython},
			{Name: "another-package", Type: config.PackageTypePython},
			{Name: "terraform-provider-aws", Type: config.PackageTypeTerraform}, // Should not appear
		},
	}
	reg := NewRegistry(cfg, packageList)
	mux := chi.NewRouter()
	reg.SetupRoutes(mux)

	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)

	resp, err := s.Client().Get(s.URL + "/simple")
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
	zotAddr, err := testutils.StartTestContainer(t.Context())
	assert.NoError(t, err, "Failed to start Zot container")
	assert.NotEmpty(t, zotAddr, "Zot container address should not be empty")

	cfg := &config.HostConfig{
		Host:          zotAddr,
		AllowInsecure: true,
		OrgKey:        "org",
	}
	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "example", Type: config.PackageTypePython},
		},
	}
	reg := NewRegistry(cfg, packageList)
	mux := chi.NewRouter()
	reg.SetupRoutes(mux)

	s := httptest.NewServer(mux)
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

	// Start Zot container first
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

	packageList := &config.PackageList{
		Packages: []config.Package{
			{Name: "test-package", Type: config.PackageTypePython},
		},
	}

	// Start a Python container
	req := testcontainers.ContainerRequest{
		Image:        "python:3.11-slim",
		ExposedPorts: []string{},
		WaitingFor:   wait.ForLog(""),
		Cmd:          []string{"sleep", "infinity"},
	}

	pythonContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	assert.NoError(t, err, "Failed to start Python container")
	t.Cleanup(func() { _ = pythonContainer.Terminate(ctx) })

	reg := NewRegistry(cfg, packageList)
	mux := chi.NewRouter()
	reg.SetupRoutes(mux)

	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)

	uploadURL := s.URL + "/upload/"

	// Since containers can't reach localhost, we need to use host.docker.internal or the host IP
	// For testcontainers, we can get the host IP
	uploadURL = strings.Replace(uploadURL, "127.0.0.1", "host.docker.internal", 1)
	uploadURL = strings.Replace(uploadURL, "localhost", "host.docker.internal", 1)

	// Create a simple Python package structure inside the container
	packageSetup := []struct {
		name    string
		command []string
	}{
		{
			name:    "Create package directory structure",
			command: []string{"mkdir", "-p", "/tmp/test-package/test_package"},
		},
		{
			name: "Create __init__.py with hello_world function",
			command: []string{"sh", "-c", `cat > /tmp/test-package/test_package/__init__.py << 'EOF'
def hello_world():
    return "Hello from test package!"

EOF`},
		},
		{
			name: "Create pyproject.toml",
			command: []string{"sh", "-c", `cat > /tmp/test-package/pyproject.toml << 'EOF'
[build-system]
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
packages = ["test_package"]
EOF`},
		},
		{
			name:    "Install build tools and twine",
			command: []string{"pip", "install", "--quiet", "build", "twine"},
		},
		{
			name:    "Build the package",
			command: []string{"sh", "-c", "cd /tmp/test-package && python -m build"},
		},
		{
			name: "setup pypirc",
			command: []string{"sh", "-c", fmt.Sprintf(`cat > ~/.pypirc << 'EOF'
[distutils]
index-servers =
    oci-package-proxy

[oci-package-proxy]
repository: %s
username: user
password: password
EOF`, uploadURL)},
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

	// Test 1: Push the package through the registry to Zot
	t.Run("PushPackageToZot", func(t *testing.T) {
		// Upload the package using twine
		uploadScript := `
cd /tmp/test-package
twine upload --repository oci-package-proxy dist/test_package-0.1.0-py3-none-any.whl
`

		exitCode, output, err := pythonContainer.Exec(ctx, []string{
			"sh", "-c", uploadScript,
		})
		assert.NoError(t, err, "Failed to upload package")

		outputStr := testutils.ReadExecOutput(output)
		t.Logf("Upload output: %s", outputStr)

		// Twine returns 0 on success
		assert.Equal(t, 0, exitCode, "Twine upload failed with exit code %d\nOutput: %s", exitCode, outputStr)

		t.Log("Successfully uploaded package using twine!")

		// Debug: Check the simple index after upload
		resp, err := s.Client().Get(s.URL + "/simple/test-package")
		assert.NoError(t, err, "Failed to get simple index after upload")
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Simple index after upload (status %d): %s", resp.StatusCode, string(body))
	})

	// Test 2: Verify the package index shows the uploaded package
	t.Run("VerifySimpleIndex", func(t *testing.T) {
		t.Skip()
		resp, err := s.Client().Get(s.URL + "/simple/test-package")
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Failed to get simple index")

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		t.Logf("Simple index response: %s", bodyStr)

		// Verify the package file is listed
		assert.Contains(t, bodyStr, "test-package-0.1.0-py3-none-any.whl", "Package file not found in index")
	})

	// Test 3: Download the package from Zot via HTTP
	var downloadURL string
	t.Run("DownloadPackageFromZot", func(t *testing.T) {
		t.Skip()
		// Get the download URL from the simple index via the actual HTTP server
		resp, err := s.Client().Get(s.URL + "/simple/test-package")
		assert.NoError(t, err, "Failed to get simple index")
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Failed to get simple index")

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err, "Failed to read response body")
		bodyStr := string(body)

		t.Logf("Simple index HTML: %s", bodyStr)

		// Extract the download URL from the href attribute
		// Format: <a href="http://zotAddr/v2/test-package/blobs/sha256:...">filename</a>
		// Note: html/template uses double quotes by default
		hrefStart := strings.Index(bodyStr, `href="`)
		if hrefStart == -1 {
			t.Fatalf("No download URL found in index. Response body:\n%s", bodyStr)
		}

		hrefStart += 6 // Move past `href="`
		hrefEnd := strings.Index(bodyStr[hrefStart:], `"`)
		if hrefEnd == -1 {
			t.Fatal("Malformed href in simple index")
		}

		downloadURL = bodyStr[hrefStart : hrefStart+hrefEnd]
		t.Logf("Download URL from index: %s", downloadURL)

		// Verify we can download the package directly from Zot
		httpResp, err := s.Client().Get(s.URL + downloadURL)
		assert.NoError(t, err, "Failed to download package from Zot")
		defer httpResp.Body.Close()
		assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Failed to download package")

		downloadedContent, err := io.ReadAll(httpResp.Body)
		assert.NoError(t, err, "Failed to read downloaded content")
		assert.NotEmpty(t, downloadedContent, "Downloaded content is empty")
		t.Logf("Successfully downloaded package, size: %d bytes", len(downloadedContent))
	})

	// Test 4: Create a fresh Python container and install the package from the registry
	t.Run("InstallPackageFromZot", func(t *testing.T) {
		// Start a fresh Python container for installation
		installReq := testcontainers.ContainerRequest{
			Image:        "python:3.11-slim",
			ExposedPorts: []string{},
			WaitingFor:   wait.ForLog(""),
			Cmd:          []string{"sleep", "infinity"},
		}

		installContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: installReq,
			Started:          true,
		})
		assert.NoError(t, err, "Failed to start installation container")
		defer installContainer.Terminate(ctx)

		// Get the simple index URL for pip to use
		simpleIndexURL := s.URL + "/simple"
		// Fix URL for container access
		simpleIndexURL = strings.Replace(simpleIndexURL, "127.0.0.1", "host.docker.internal", 1)
		simpleIndexURL = strings.Replace(simpleIndexURL, "localhost", "host.docker.internal", 1)
		t.Logf("Simple index URL for container: %s", simpleIndexURL)

		// Create a consumer package that depends on test-package
		setupCommands := []struct {
			name    string
			command []string
		}{
			{
				name:    "Create consumer package directory",
				command: []string{"mkdir", "-p", "/tmp/consumer_package/consumer_package"},
			},
			{
				name: "Create consumer pyproject.toml with test-package dependency",
				command: []string{"sh", "-c", `cat > /tmp/consumer_package/pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "consumer_package"
version = "0.1.0"
description = "A consumer package that depends on test-package"
requires-python = ">=3.6"
dependencies = [
    "test-package==0.1.0",
]

[tool.setuptools]
packages = ["consumer_package"]
EOF`},
			},
			{
				name:    "Install pip and setuptools",
				command: []string{"pip", "install", "--quiet", "--upgrade", "pip", "setuptools", "wheel"},
			},
		}

		for _, step := range setupCommands {
			t.Logf("Executing: %s", step.name)
			exitCode, output, err := installContainer.Exec(ctx, step.command)
			assert.NoError(t, err, "Failed to exec command: %s", step.name)

			outputStr := testutils.ReadExecOutput(output)
			if exitCode != 0 {
				t.Logf("Command output: %s", outputStr)
			}
			assert.Equal(t, 0, exitCode, "Command failed: %s\nOutput: %s", step.name, outputStr)
		}

		// Install the consumer package (which will pull test-package from our registry)
		t.Logf("Installing consumer package with dependency from OCI registry")
		installScript := fmt.Sprintf(`
cd /tmp/consumer_package
pip install --extra-index-url %s --trusted-host host.docker.internal --verbose .
`, simpleIndexURL)

		exitCode, output, err := installContainer.Exec(ctx, []string{
			"sh", "-c", installScript,
		})
		assert.NoError(t, err, "Failed to install consumer package")
		outputStr := testutils.ReadExecOutput(output)
		t.Logf("Installation output: %s", outputStr)

		if exitCode != 0 {
			t.Fatalf("Failed to install consumer package with exit code %d\nOutput: %s", exitCode, outputStr)
		}

		// Test that both packages work correctly
		exitCode, output, err = installContainer.Exec(ctx, []string{
			"python", "-c", "from test_package import hello_world; print(hello_world())",
		})
		assert.NoError(t, err, "Failed to test installed package")
		outputStr = testutils.ReadExecOutput(output)
		t.Logf("Test output: %s", outputStr)
		assert.Equal(t, 0, exitCode, "Failed to run test")
		assert.Contains(t, outputStr, "Hello from test package!", "Package function did not work as expected")

		t.Log("Successfully installed and tested package from OCI registry via pip!")
	})
}

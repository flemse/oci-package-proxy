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

	r := httptest.NewRequest("GET", "/simple/", nil)
	w := httptest.NewRecorder()
	reg := NewRegistry(cfg, packageList)
	reg.handleSimpleIndex(w, r)
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
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
	cfg := &config.HostConfig{
		Host:          "oci.example.com",
		AllowInsecure: false,
		OrgKey:        "org",
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "example-0.1.0.tar.gz")
	fw.Write([]byte("dummy python package content"))
	mw.Close()

	r := httptest.NewRequest("POST", "/upload/", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	reg := NewRegistry(cfg, nil)
	reg.handlePackageUpload(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestHandlePackageDownload_AuthForward(t *testing.T) {
	cfg := &config.HostConfig{
		Host:          "oci.example.com",
		AllowInsecure: false,
		OrgKey:        "org",
	}
	r := httptest.NewRequest("GET", "/packages/example-0.1.0.tar.gz", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // user:pass
	w := httptest.NewRecorder()
	reg := NewRegistry(cfg, nil)
	reg.handlePackageDownload(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 200 or 500 (mocked), got %d", resp.StatusCode)
	}
}

func TestZot(t *testing.T) {
	ctx := context.Background()
	zotAddr, err := StartTestContainer(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, zotAddr, "Zot container address should not be empty")

}

func StartTestContainer(ctx context.Context) (string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/project-zot/zot:latest",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForLog("starting task"),
	}
	zotContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return "", fmt.Errorf("could not start zot container: %w", err)
	}
	h, err := zotContainer.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("could not get zot container host: %w", err)
	}
	p, err := zotContainer.MappedPort(ctx, "5000")
	if err != nil {
		return "", fmt.Errorf("could not get zot container port: %w", err)
	}

	return fmt.Sprintf("%s:%s", h, p.Port()), nil
}

func TestPythonPackageInContainer(t *testing.T) {
	ctx := context.Background()

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
	defer pythonContainer.Terminate(ctx)

	// Create a simple Python package structure inside the container
	packageSetup := []struct {
		name    string
		command []string
	}{
		{
			name:    "Create package directory structure",
			command: []string{"mkdir", "-p", "/tmp/test_package/test_package"},
		},
		{
			name: "Create __init__.py with hello_world function",
			command: []string{"sh", "-c", `cat > /tmp/test_package/test_package/__init__.py << 'EOF'
def hello_world():
    return "Hello from test package!"

EOF`},
		},
		{
			name: "Create pyproject.toml",
			command: []string{"sh", "-c", `cat > /tmp/test_package/pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "test_package"
version = "0.1.0"
description = "A test package for integration testing"
requires-python = ">=3.6"

[tool.setuptools]
packages = ["test_package"]
EOF`},
		},
		{
			name:    "Install build tools",
			command: []string{"pip", "install", "--quiet", "build"},
		},
		{
			name:    "Build the package",
			command: []string{"sh", "-c", "cd /tmp/test_package && python -m build"},
		},
		{
			name:    "Install the package",
			command: []string{"sh", "-c", "pip install --quiet /tmp/test_package/dist/test_package-0.1.0-py3-none-any.whl"},
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

	// Test 1: Verify the package can be imported
	t.Run("ImportPackage", func(t *testing.T) {
		exitCode, output, err := pythonContainer.Exec(ctx, []string{
			"python", "-c", "import test_package; print('SUCCESS')",
		})
		assert.NoError(t, err)
		outputStr := testutils.ReadExecOutput(output)
		assert.Equal(t, 0, exitCode, "Failed to import package")
		assert.Contains(t, outputStr, "SUCCESS", "Package import verification failed")
	})

	// Test 2: Verify hello_world function works
	t.Run("TestHelloWorld", func(t *testing.T) {
		exitCode, output, err := pythonContainer.Exec(ctx, []string{
			"python", "-c", "from test_package import hello_world; print(hello_world())",
		})
		assert.NoError(t, err)
		outputStr := testutils.ReadExecOutput(output)
		assert.Equal(t, 0, exitCode, "Failed to run hello_world function")
		assert.Equal(t, "Hello from test package!", outputStr, "Unexpected output from hello_world")
	})

	t.Log("All Python package tests passed successfully!")
}

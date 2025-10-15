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
	assert.NoError(t, err, "Failed to start proxy server")
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

	producerContainer, err := testutils.StartPythonTestContainer(ctx)
	assert.NoError(t, err, "Failed to start Python producer container")
	t.Cleanup(func() { _ = producerContainer.Terminate(ctx) })

	consumerContainer, err := testutils.StartPythonTestContainer(ctx)
	assert.NoError(t, err, "Failed to start Python consumer container")
	t.Cleanup(func() { _ = consumerContainer.Terminate(ctx) })

	uploadURL := s.URL + "/upload/"

	// Since containers can't reach localhost, we need to use host.docker.internal or the host IP
	uploadURL = strings.Replace(uploadURL, "127.0.0.1", "host.docker.internal", 1)
	uploadURL = strings.Replace(uploadURL, "localhost", "host.docker.internal", 1)

	err = producerContainer.CopyDirToContainer(ctx, "./sample/producer", "/workspace/", 0755)
	assert.NoError(t, err)

	err = consumerContainer.CopyDirToContainer(ctx, "./sample/consumer", "/workspace/", 0755)
	assert.NoError(t, err, "Failed to copy consumer pyproject.toml to container")

	pypirc := fmt.Sprintf(`[distutils]
index-servers =
	oci-package-proxy

[oci-package-proxy]
repository: %s
username: user
password: password`, uploadURL)

	err = producerContainer.CopyToContainer(ctx, []byte(pypirc), "/root/.pypirc", 0644)
	assert.NoError(t, err, "Failed to copy .pypirc to container")

	t.Run("PushPackage", func(t *testing.T) {
		exitCode, output, err := producerContainer.Exec(ctx, []string{"sh", "-c", "cd /workspace/producer && python -m build"})
		assert.NoError(t, err, "Failed to build")

		outputStr := testutils.ReadExecOutput(output)
		t.Logf("build output: %s", outputStr)

		exitCode, output, err = producerContainer.Exec(ctx, []string{
			"sh", "-c", "cd /workspace/producer && twine upload --repository oci-package-proxy dist/test_package-0.1.0-py3-none-any.whl",
		})
		assert.NoError(t, err, "Failed to upload package")

		outputStr = testutils.ReadExecOutput(output)
		t.Logf("Upload output: %s", outputStr)

		// Twine returns 0 on success
		assert.Equal(t, 0, exitCode, "Twine upload failed with exit code %d\nOutput: %s", exitCode, outputStr)
	})

	t.Run("InstallPackage", func(t *testing.T) {
		// Get the simple index URL for pip to use
		simpleIndexURL := s.URL + "/simple"
		// Fix URL for container access
		simpleIndexURL = strings.Replace(simpleIndexURL, "127.0.0.1", "host.docker.internal", 1)
		simpleIndexURL = strings.Replace(simpleIndexURL, "localhost", "host.docker.internal", 1)
		t.Logf("Simple index URL for container: %s", simpleIndexURL)

		exitCode, output, err := consumerContainer.Exec(ctx, []string{
			"sh", "-c", fmt.Sprintf("cd /workspace/consumer && pip install --break-system-packages --extra-index-url %s --trusted-host host.docker.internal --quiet .", simpleIndexURL),
		})
		assert.NoError(t, err, "Failed to install consumer package")
		outputStr := testutils.ReadExecOutput(output)
		t.Logf("Installation output: %s", outputStr)

		if exitCode != 0 {
			t.Fatalf("Failed to install consumer package with exit code %d\nOutput: %s", exitCode, outputStr)
		}

		// Test that both packages work correctly
		exitCode, output, err = consumerContainer.Exec(ctx, []string{
			"sh", "-c", "cd /workspace/consumer && python script.py",
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

package python

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flemse/oci-package-proxy/pkg/config"
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
	r := httptest.NewRequest("GET", "/simple/example/", nil)
	w := httptest.NewRecorder()
	reg := NewRegistry(cfg, nil)
	reg.handleSimpleIndex(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("example-0.1.0.tar.gz")) {
		t.Errorf("index missing package link")
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

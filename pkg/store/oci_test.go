package store

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestOCIStore(t *testing.T) {
	ctx := t.Context()
	zotAddr, err := testutils.StartTestContainer(ctx)
	require.NoError(t, err, "Failed to start Zot container")
	require.NotEmpty(t, zotAddr, "Zot container address should not be empty")
	t.Logf("Zot container running at: %s", zotAddr)
	cfg := &config.HostConfig{
		AllowInsecure: true,
		Host:          strings.TrimPrefix(zotAddr, "http://"),
		OrgKey:        "test-org",
	}

	s, err := NewStore(cfg, "test-project", nil)
	assert.NoError(t, err)

	files := []struct {
		file    string
		content string
		tag     string
	}{
		{
			file:    "file1.txt",
			content: "value1",
			tag:     "v1",
		},
		{
			file:    "file2.txt",
			content: "value2",
			tag:     "v2",
		},
	}

	for _, f := range files {
		err = s.PushFile(t.Context(), strings.NewReader(f.content), f.file, f.tag)
		assert.NoError(t, err)
	}

	t.Run("GetShasum", func(t *testing.T) {
		t.Skip("needs to use other push method for shasum to be set")
		shasums, err := s.Shasums(ctx, "v1")
		assert.NoError(t, err)
		assert.NotEmpty(t, shasums)
	})

	t.Run("GetDownloadUrls", func(t *testing.T) {
		urls, err := s.DownloadUrls(ctx, "v1")
		assert.NoError(t, err)
		assert.NotEmpty(t, urls)
		resp, err := http.Get(urls["file1.txt"])
		assert.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "value1", string(body))
	})

	t.Run("GetVersions", func(t *testing.T) {
		versions, err := s.Versions(ctx)
		assert.NoError(t, err)
		assert.EqualValues(t, []string{"1", "2"}, versions) // TODO: consider if we should keep "v" and only strip it in terraform cases
	})
}

func TestGetPackages_GHCR_Success(t *testing.T) {
	t.Skip("skipping test that requires GHCR access token")
	ctx := context.Background()
	host := "ghcr.io/lego"
	//repoName := "novus/applicationmanagement"
	registry, err := remote.NewRegistry(host)
	assert.NoError(t, err)
	c := auth.DefaultClient
	to, err := os.ReadFile("/Users/dkFleThe/src/flemse/oci-package-proxy/tmp/GH_TOKEN")
	assert.NoError(t, err)
	c.Credential = func(ctx context.Context, registry string) (auth.Credential, error) {
		return auth.Credential{
			Username: "oauth2",
			Password: string(to),
		}, nil
	}

	assert.NoError(t, err)
	var repos []string
	err = registry.Repositories(ctx, "", func(repositories []string) error {
		repos = append(repos, repositories...)
		return nil
	})
	assert.NoError(t, err)

	assert.NotEmpty(t, repos)
}

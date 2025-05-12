package store

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestFetchTags(t *testing.T) {
	ctx := context.Background()
	host := "localhost:5001"
	repoName := "appmgmt"
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", host, repoName))
	repo.PlainHTTP = true
	assert.NoError(t, err)
	expectedTagList := []string{"v1"}
	var actualTagList []string

	err = repo.Tags(ctx, "", func(tags []string) error {
		actualTagList = append(actualTagList, tags...)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, expectedTagList, actualTagList)
}

func TestManifest(t *testing.T) {
	ctx := context.Background()
	host := "localhost:5001"
	repoName := "appmgmt"
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", host, repoName))
	repo.PlainHTTP = true
	assert.NoError(t, err)

	desc, err := repo.Resolve(ctx, "appmgmt:v1")
	assert.NoError(t, err)
	assert.NotNil(t, desc)
}

func TestShasumsFromIndex(t *testing.T) {
	ctx := context.Background()
	host := "localhost:5001"
	repoName := "appmgmt"
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", host, repoName))
	repo.PlainHTTP = true
	assert.NoError(t, err)
	oci := NewStore(repo)

	shasums, err := oci.Shasums(ctx, "v1")
	assert.NoError(t, err)
	assert.NotEmpty(t, shasums)
}

func TestDownloadUrlsFromIndex(t *testing.T) {
	ctx := context.Background()
	host := "localhost:5001"
	repoName := "appmgmt"
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", host, repoName))
	repo.PlainHTTP = true
	assert.NoError(t, err)
	oci := NewStore(repo)

	urls, err := oci.DownloadUrls(ctx, "v1")
	assert.NoError(t, err)
	assert.NotEmpty(t, urls)
}

func TestGetOciStore(t *testing.T) {
	store, err := oci.New(t.TempDir())
	assert.NoError(t, err)
	ctx := context.Background()
	host := "localhost:5001"
	repoName := "appmgmt"
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", host, repoName))
	repo.PlainHTTP = true
	assert.NoError(t, err)
	// 2. Copy from the remote repository to the OCI layout store
	tag := "v1"
	manifestDescriptor, err := oras.Copy(ctx, repo, tag, store, tag, oras.DefaultCopyOptions)
	assert.NoError(t, err)
	assert.NotNil(t, manifestDescriptor)
}

func TestGetVersions(t *testing.T) {
	ctx := context.Background()
	host := "localhost:5001"
	repoName := "novus/applicationmanagement"
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", host, repoName))
	repo.PlainHTTP = true
	assert.NoError(t, err)
	oci := NewStore(repo)

	versions, err := oci.Versions(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, versions)
}

func TestGetPackages_GHCR_Success(t *testing.T) {
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

func NewRepository(reference string) (*remote.Repository, error) {
	token := os.Getenv("GITHUB_TOKEN")
	repo, err := remote.NewRepository(reference)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}
	if token == "" {
		return repo, nil
	}

	c := auth.DefaultClient
	c.Credential = func(ctx context.Context, registry string) (auth.Credential, error) {
		return auth.Credential{
			Username: "oauth2", // GitHub requires "oauth2" as the username for PATs
			Password: token,
		}, nil
	}

	repo.Client = c
	return repo, nil
}

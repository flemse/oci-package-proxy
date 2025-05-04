package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
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

func TestFetch(t *testing.T) {
	ctx := context.Background()
	host := "localhost:5001"
	repoName := "appmgmt"
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", host, repoName))
	repo.PlainHTTP = true
	assert.NoError(t, err)

	r, _, err := repo.FetchReference(ctx, "v1")
	assert.NoError(t, err)
	assert.NotNil(t, r)
	rc, err := repo.Fetch(ctx, r)
	assert.NoError(t, err)
	defer rc.Close()
	var s ocispec.Index
	err = json.NewDecoder(rc).Decode(&s)
	assert.NoError(t, err)
	assert.NotNil(t, s)
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

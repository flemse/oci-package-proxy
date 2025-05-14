package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	// ArtifactType is the artifact type for Terraform providers.
	ArtifactType = "application/vnd.tf.provider.v1+json"
	// FileDigestAnnotation is the annotation key for the original file digest.
	FileDigestAnnotation = "original-file-digest"
	// FileNameAnnotation is the annotation key for the original file name.
	FileNameAnnotation = "original-filename"
	// ShasumSignatureAnnotation is the annotation key for the shasum signature.
	ShasumSignatureAnnotation = "shasum-signature-encoded"
	// ShasumAnnotation is the annotation key for the shasum.
	ShasumAnnotation = "shasum"
)

type Store struct {
	repo *remote.Repository
}

type DownloadInfo struct {
	Filename string
	Url      string
	Digest   string
}

func NewStore(ociHost, packageName string, creds *auth.Credential, allowInsecure bool) (*Store, error) {
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", ociHost, packageName))
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	repo.PlainHTTP = allowInsecure
	c := auth.DefaultClient
	if creds != nil {
		c.Credential = func(ctx context.Context, hostport string) (auth.Credential, error) {
			return *creds, nil
		}
	}

	repo.Client = c
	return &Store{
		repo: repo,
	}, nil
}

func (s *Store) Versions(ctx context.Context) ([]string, error) {
	var tags []string
	err := s.repo.Tags(ctx, "", func(tagList []string) error {
		tags = append(tags, tagList...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tags: %w", err)
	}
	for i, tag := range tags {
		if strings.HasPrefix(tag, "v") {
			tags[i] = strings.TrimPrefix(tag, "v")
		}
	}
	return tags, nil
}

func (s *Store) Shasums(ctx context.Context, tag string) ([]byte, error) {
	idx, err := s.getIndex(ctx, tag)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get index: %w", err)
	}

	if encodedSig, ok := idx.Annotations[ShasumAnnotation]; ok {
		return base64.StdEncoding.DecodeString(encodedSig)
	}

	return []byte{}, fmt.Errorf("shasums found")
}

func (s *Store) DownloadUrls(ctx context.Context, tag string) (map[string]string, error) {
	idx, err := s.getIndex(ctx, tag)
	if err != nil {
		return map[string]string{}, fmt.Errorf("failed to get index: %w", err)
	}
	blobUrls := make(map[string]string)
	for _, d := range idx.Manifests {
		if d.ArtifactType == ArtifactType {
			blobURL := fmt.Sprintf("%s://%s/v2/%s/blobs/sha256:%s", s.getProtocol(), s.repo.Reference.Registry, s.repo.Reference.Repository, d.Annotations[FileDigestAnnotation])
			blobUrls[d.Annotations[FileNameAnnotation]] = blobURL
		}
	}
	if len(blobUrls) == 0 {
		return nil, fmt.Errorf("no blob URLs found")
	}
	return blobUrls, nil
}

func (s *Store) DownloadUrlForPlatform(ctx context.Context, tag, os, arch string) (DownloadInfo, error) {
	idx, err := s.getIndex(ctx, tag)
	if err != nil {
		return DownloadInfo{}, fmt.Errorf("failed to get index: %w", err)
	}
	for _, d := range idx.Manifests {
		if d.ArtifactType == ArtifactType && d.Platform.OS == os && d.Platform.Architecture == arch {
			return DownloadInfo{
				Filename: d.Annotations[FileNameAnnotation],
				Url:      fmt.Sprintf("%s://%s/v2/%s/blobs/sha256:%s", s.getProtocol(), s.repo.Reference.Registry, s.repo.Reference.Repository, d.Annotations[FileDigestAnnotation]),
				Digest:   d.Annotations[FileDigestAnnotation],
			}, nil
		}
	}
	return DownloadInfo{}, fmt.Errorf("no blob URL found for OS %s and architecture %s", os, arch)
}

func (s *Store) GetFileContent(ctx context.Context, tag, os, arch string) (io.ReadCloser, error) {
	idx, err := s.getIndex(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to get index: %w", err)
	}
	for _, d := range idx.Manifests {
		if d.ArtifactType == ArtifactType && d.Platform.OS == os && d.Platform.Architecture == arch {
			reader, err := s.repo.Fetch(ctx, d)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch file content: %w", err)
			}
			defer reader.Close()
			var manifest ocispec.Manifest
			if err := json.NewDecoder(reader).Decode(&manifest); err != nil {
				return nil, fmt.Errorf("failed to decode manifest: %w", err)
			}
			lr, err := s.repo.Fetch(ctx, manifest.Layers[0])

			return lr, nil
		}
	}
	return nil, fmt.Errorf("no file content found for OS %s and architecture %s", os, arch)
}

func (s *Store) GetSignature(ctx context.Context, tag string) ([]byte, error) {
	idx, err := s.getIndex(ctx, tag)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get index: %w", err)
	}

	if encodedSig, ok := idx.Annotations[ShasumSignatureAnnotation]; ok {
		return base64.StdEncoding.DecodeString(encodedSig)
	}

	return []byte{}, fmt.Errorf("no signature found")
}

func (s *Store) getIndex(ctx context.Context, ref string) (*ocispec.Index, error) {
	indexDesc, err := s.repo.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	indexReader, err := s.repo.Fetch(ctx, indexDesc)
	if err != nil {
		return nil, err
	}
	defer indexReader.Close()

	var index ocispec.Index
	if err := json.NewDecoder(indexReader).Decode(&index); err != nil {
		return nil, fmt.Errorf("failed to decode index: %w", err)
	}
	return &index, nil
}

func (s *Store) getProtocol() string {
	if s.repo.PlainHTTP {
		return "http"
	}
	return "https"
}

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	// ArtifactType is the artifact type for Terraform providers.
	ArtifactType = "application/vnd.tf.provider.v1+json"
	// FileDigestAnnotation is the annotation key for the original file digest.
	FileDigestAnnotation = "original-file-digest"
	// FileNameAnnotation is the annotation key for the original file name.
	FileNameAnnotation = "original-filename"
)

type Store struct {
	repo *remote.Repository
}

type DownloadInfo struct {
	Filename string
	Url      string
	Digest   string
}

func NewStore(repo *remote.Repository) *Store {
	return &Store{repo: repo}
}

func (s *Store) getProtocol() string {
	if s.repo.PlainHTTP {
		return "http"
	}
	return "https"
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

func (s *Store) Shasums(ctx context.Context, tag string) (string, error) {
	idx, err := s.getIndex(ctx, tag)
	if err != nil {
		return "", fmt.Errorf("failed to get index: %w", err)
	}
	var descriptors []ocispec.Descriptor
	for _, d := range idx.Manifests {
		if d.ArtifactType == ArtifactType {
			descriptors = append(descriptors, d)
		}
	}
	if len(descriptors) == 0 {
		return "", fmt.Errorf("no descriptors found")
	}

	buf := strings.Builder{}
	for _, d := range descriptors {
		buf.WriteString(d.Annotations[FileDigestAnnotation])
		buf.WriteString(" ")
		buf.WriteString(d.Annotations[FileNameAnnotation])
		buf.WriteString("\n")
	}

	return buf.String(), nil
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

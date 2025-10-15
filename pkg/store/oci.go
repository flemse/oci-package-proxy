package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	_package "github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
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

func NewStore(cfg *_package.HostConfig, packageName string, creds *auth.Credential) (*Store, error) {
	repo, err := remote.NewRepository(fmt.Sprintf("%s/%s", cfg.Host, packageName))
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	repo.PlainHTTP = cfg.AllowInsecure
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

	// If this is an outer index with a single manifest that's also an index,
	// fetch and return the inner index instead
	if len(index.Manifests) == 1 && index.Manifests[0].MediaType == ocispec.MediaTypeImageIndex {
		innerIndexReader, err := s.repo.Fetch(ctx, index.Manifests[0])
		if err != nil {
			return nil, fmt.Errorf("failed to fetch inner index: %w", err)
		}
		defer innerIndexReader.Close()

		var innerIndex ocispec.Index
		if err := json.NewDecoder(innerIndexReader).Decode(&innerIndex); err != nil {
			return nil, fmt.Errorf("failed to decode inner index: %w", err)
		}
		return &innerIndex, nil
	}

	return &index, nil
}

func (s *Store) getProtocol() string {
	if s.repo.PlainHTTP {
		return "http"
	}
	return "https"
}

// PushFile uploads a file to the OCI registry with the specified tag and metadata
func (s *Store) PushFile(ctx context.Context, fileContent io.Reader, filename, tag string) error {
	// Read the file content into memory to calculate digest
	fileData, err := io.ReadAll(fileContent)
	if err != nil {
		return fmt.Errorf("failed to read file content: %w", err)
	}

	// Calculate digest using opencontainers/go-digest
	blobDigest := digest.FromBytes(fileData)

	// Create blob descriptor for the file
	blobDesc := ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    blobDigest,
		Size:      int64(len(fileData)),
	}

	// Push the blob (file content)
	if err := s.repo.Push(ctx, blobDesc, strings.NewReader(string(fileData))); err != nil {
		return fmt.Errorf("failed to push blob: %w", err)
	}

	// Create empty config
	emptyConfig := []byte("{}")
	configDigest := digest.FromBytes(emptyConfig)
	configDesc := ocispec.Descriptor{
		MediaType: "application/vnd.oci.empty.v1+json",
		Digest:    configDigest,
		Size:      int64(len(emptyConfig)),
	}

	// Push the config
	if err := s.repo.Push(ctx, configDesc, strings.NewReader(string(emptyConfig))); err != nil {
		return fmt.Errorf("failed to push config: %w", err)
	}

	// Create manifest with the blob as a layer
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{blobDesc},
		Annotations: map[string]string{
			FileNameAnnotation:   filename,
			FileDigestAnnotation: blobDigest.Encoded(),
		},
	}

	// Marshal and push the manifest
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	manifestDigest := digest.FromBytes(manifestData)
	manifestDesc := ocispec.Descriptor{
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       manifestDigest,
		Size:         int64(len(manifestData)),
		ArtifactType: ArtifactType,
		Platform: &ocispec.Platform{
			OS:           "",
			Architecture: "",
		},
		Annotations: map[string]string{
			FileNameAnnotation:   filename,
			FileDigestAnnotation: blobDigest.Encoded(),
		},
	}

	if err := s.repo.Push(ctx, manifestDesc, strings.NewReader(string(manifestData))); err != nil {
		return fmt.Errorf("failed to push manifest: %w", err)
	}

	// Create or update index
	var index ocispec.Index
	existingIndex, err := s.getIndex(ctx, tag)
	if err == nil {
		// Update existing index
		index = *existingIndex
		// Append the new manifest to the index
		index.Manifests = append(index.Manifests, manifestDesc)
	} else {
		// Create new index
		index = ocispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ocispec.MediaTypeImageIndex,
			Manifests: []ocispec.Descriptor{manifestDesc},
		}
	}

	// Marshal and push the index
	indexData, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	indexDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, indexData)

	if err := s.repo.Push(ctx, indexDesc, strings.NewReader(string(indexData))); err != nil {
		return fmt.Errorf("failed to push index: %w", err)
	}

	// Tag the index
	if err := s.repo.Tag(ctx, indexDesc, tag); err != nil {
		return fmt.Errorf("failed to tag index: %w", err)
	}

	_ = sha256.Sum256      // Keep import
	_ = base64.StdEncoding // Keep import

	return nil
}

// ProviderFile represents a file to be uploaded as part of a provider bundle
type ProviderFile struct {
	Name    string
	Content []byte
	OS      string
	Arch    string
}

// PushProviderBundle uploads a complete Terraform provider bundle to the OCI registry
func (s *Store) PushProviderBundle(ctx context.Context, tag string, files []ProviderFile, shasums []byte, signature []byte) error {
	innerImageIndex := ocispec.Index{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   ocispec.MediaTypeImageIndex,
		Annotations: map[string]string{},
	}

	// Store shasums if provided
	if len(shasums) > 0 {
		encodedShasum := base64.StdEncoding.EncodeToString(shasums)
		innerImageIndex.Annotations[ShasumAnnotation] = encodedShasum
	}

	// Store signature if provided
	if len(signature) > 0 {
		encodedSig := base64.StdEncoding.EncodeToString(signature)
		innerImageIndex.Annotations[ShasumSignatureAnnotation] = encodedSig
	}

	// Process each file
	for _, file := range files {
		// Calculate file digest
		fileDigest := digest.FromBytes(file.Content)

		// Create blob descriptor
		blobDesc := ocispec.Descriptor{
			MediaType:    ocispec.MediaTypeImageLayerGzip,
			Digest:       fileDigest,
			ArtifactType: ArtifactType,
			Platform: &ocispec.Platform{
				OS:           file.OS,
				Architecture: file.Arch,
			},
			Size: int64(len(file.Content)),
		}

		// Push the blob
		if err := s.repo.Push(ctx, blobDesc, strings.NewReader(string(file.Content))); err != nil {
			return fmt.Errorf("failed to push blob for %s: %w", file.Name, err)
		}

		// Create config with platform info
		config := map[string]string{
			"os":           file.OS,
			"architecture": file.Arch,
		}
		configData, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config for %s: %w", file.Name, err)
		}

		configDigest := digest.FromBytes(configData)
		configDesc := ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configData)),
		}

		// Push the config
		if err := s.repo.Push(ctx, configDesc, strings.NewReader(string(configData))); err != nil {
			return fmt.Errorf("failed to push config for %s: %w", file.Name, err)
		}

		// Create annotations for the manifest
		annotations := map[string]string{
			FileNameAnnotation:   file.Name,
			FileDigestAnnotation: fileDigest.Encoded(),
		}

		// Create manifest
		manifest := ocispec.Manifest{
			Versioned:    specs.Versioned{SchemaVersion: 2},
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: ArtifactType,
			Config:       configDesc,
			Layers: []ocispec.Descriptor{
				blobDesc,
			},
			Annotations: annotations,
		}

		manifestData, err := json.Marshal(manifest)
		if err != nil {
			return fmt.Errorf("failed to marshal manifest for %s: %w", file.Name, err)
		}

		manifestDigest := digest.FromBytes(manifestData)
		manifestDesc := ocispec.Descriptor{
			MediaType:    ocispec.MediaTypeImageManifest,
			Digest:       manifestDigest,
			Size:         int64(len(manifestData)),
			Annotations:  annotations,
			ArtifactType: ArtifactType,
			Platform: &ocispec.Platform{
				OS:           file.OS,
				Architecture: file.Arch,
			},
		}

		// Set platform info if available
		if file.OS != "" || file.Arch != "" {
			manifestDesc.Platform = &ocispec.Platform{
				OS:           file.OS,
				Architecture: file.Arch,
			}
		}

		// Push the manifest
		if err := s.repo.Push(ctx, manifestDesc, strings.NewReader(string(manifestData))); err != nil {
			return fmt.Errorf("failed to push manifest for %s: %w", file.Name, err)
		}

		// Add to inner index
		innerImageIndex.Manifests = append(innerImageIndex.Manifests, manifestDesc)
	}

	// Marshal inner index
	innerIndexData, err := json.Marshal(innerImageIndex)
	if err != nil {
		return fmt.Errorf("failed to marshal inner image index: %w", err)
	}

	innerIndexDigest := digest.FromBytes(innerIndexData)
	innerIndexDesc := ocispec.Descriptor{
		MediaType:    ocispec.MediaTypeImageIndex,
		Digest:       innerIndexDigest,
		Size:         int64(len(innerIndexData)),
		ArtifactType: ArtifactType,
		Annotations: map[string]string{
			ocispec.AnnotationRefName: tag,
		},
	}

	// Push inner index
	if err := s.repo.Push(ctx, innerIndexDesc, strings.NewReader(string(innerIndexData))); err != nil {
		return fmt.Errorf("failed to push inner index: %w", err)
	}

	// Create outer index with the inner index as a manifest
	outerImageIndex := ocispec.Index{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   ocispec.MediaTypeImageIndex,
		Annotations: map[string]string{},
		Manifests:   []ocispec.Descriptor{innerIndexDesc},
	}

	// Marshal outer index
	outerIndexData, err := json.Marshal(outerImageIndex)
	if err != nil {
		return fmt.Errorf("failed to marshal outer image index: %w", err)
	}

	outerIndexDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, outerIndexData)

	// Push outer index
	if err := s.repo.Push(ctx, outerIndexDesc, strings.NewReader(string(outerIndexData))); err != nil {
		return fmt.Errorf("failed to push outer index: %w", err)
	}

	// Tag the outer index
	if err := s.repo.Tag(ctx, outerIndexDesc, tag); err != nil {
		return fmt.Errorf("failed to tag index: %w", err)
	}

	return nil
}

// SHA256Sum calculates the SHA256 checksum of the given data
func SHA256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

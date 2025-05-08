package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/flemse/oci-package-proxy/pkg/store"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/spf13/cobra"
)

var (
	refName      string
	inputPath    string
	outPath      string
	cleanOutPath bool
)

type ManifestConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate OCI manifest list for zip files in the dist directory",
	Run: func(cmd *cobra.Command, args []string) {

		if cleanOutPath && outPath != "" {
			// Clean the output directory if it exists
			if _, err := os.Stat(outPath); err == nil {
				if err := os.RemoveAll(outPath); err != nil {
					log.Fatalf("Failed to clean output path: %v", err)
				}
			}
		}
		blobsDir := filepath.Join(outPath, "blobs", "sha256")

		// Create the OCI layout directory structure
		if err := os.MkdirAll(blobsDir, os.ModePerm); err != nil {
			log.Fatalf("Failed to create OCI layout directory: %v", err)
		}

		// Create the oci-layout file
		layoutFile := filepath.Join(outPath, "oci-layout")
		if err := os.WriteFile(layoutFile, []byte(`{"imageLayoutVersion": "1.0.0"}`), os.ModePerm); err != nil {
			log.Fatalf("Failed to create oci-layout file: %v", err)
		}

		outerImageIndex := ocispec.Index{
			Versioned:   specs.Versioned{SchemaVersion: 2},
			MediaType:   ocispec.MediaTypeImageIndex,
			Annotations: map[string]string{},
		}

		innerImageIndex := ocispec.Index{
			Versioned:   specs.Versioned{SchemaVersion: 2},
			MediaType:   ocispec.MediaTypeImageIndex,
			Annotations: map[string]string{},
		}

		foundShasum := false
		foundSig := false
		//createdAt := time.Now().Format(time.RFC3339)
		err := filepath.WalkDir(inputPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if d.IsDir() {
				return nil
			}

			if strings.HasSuffix(d.Name(), "SHA256SUMS") {
				foundShasum = true
				file, err := os.Open(path)
				if err != nil {
					log.Printf("Failed to open file %s: %v", path, err)
					return nil
				}
				defer file.Close()

				data, err := io.ReadAll(file)
				if err != nil {
					log.Printf("Failed to read file %s: %v", path, err)
					return nil
				}
				encodedShasum := base64.StdEncoding.EncodeToString(data)
				innerImageIndex.Annotations[store.ShasumAnnotation] = encodedShasum
			}
			if strings.HasSuffix(d.Name(), "SHA256SUMS.sig") {
				foundSig = true
				file, err := os.Open(path)
				if err != nil {
					log.Printf("Failed to open file %s: %v", path, err)
					return nil
				}
				defer file.Close()

				data, err := io.ReadAll(file)
				if err != nil {
					log.Printf("Failed to read file %s: %v", path, err)
					return nil
				}
				encodedSig := base64.StdEncoding.EncodeToString(data)
				innerImageIndex.Annotations[store.ShasumSignatureAnnotation] = encodedSig
			}

			// Process only .zip files
			if strings.HasSuffix(d.Name(), ".zip") {
				// Open the file to calculate size and digest
				file, err := os.Open(path)
				if err != nil {
					log.Printf("Failed to open file %s: %v", path, err)
					return nil
				}
				defer file.Close()

				// Get file info
				info, err := file.Stat()
				if err != nil {
					log.Printf("Failed to get file info for %s: %v", path, err)
					return nil
				}

				layerData, err := io.ReadAll(file)
				if err != nil {
					fmt.Printf("Error reading file: %v\n", err)
					return nil
				}
				layerDigest := digest.FromBytes(layerData)
				// Copy the file to blobs/sha256 with the digest as the filename
				blobPath := filepath.Join(blobsDir, layerDigest.Encoded())
				if _, err := file.Seek(0, io.SeekStart); err != nil {
					log.Printf("Failed to reset file pointer for %s: %v", path, err)
					return nil
				}
				blobFile, err := os.Create(blobPath)
				if err != nil {
					log.Printf("Failed to create blob file %s: %v", blobPath, err)
					return nil
				}
				defer blobFile.Close()

				if _, err := io.Copy(blobFile, file); err != nil {
					log.Printf("Failed to copy file to blob %s: %v", blobPath, err)
					return nil
				}

				// Extract OS and architecture from the filename
				parts := strings.Split(d.Name(), "_")
				if len(parts) < 4 {
					log.Printf("Invalid filename format for %s", d.Name())
					return nil
				}
				osName := parts[len(parts)-2]
				arch := strings.TrimSuffix(parts[len(parts)-1], ".zip")

				config := ManifestConfig{
					OS:           osName,
					Architecture: arch,
				}
				configData, err := json.Marshal(config)
				if err != nil {
					log.Printf("Failed to marshal config for %s: %v", d.Name(), err)
					return nil
				}
				configDigest := digest.FromString(string(configData))
				configPath := filepath.Join(blobsDir, configDigest.Encoded())
				if err := os.WriteFile(configPath, configData, os.ModePerm); err != nil {
					log.Printf("Failed to write manifest file %s: %v", configPath, err)
					return nil
				}
				annotations := map[string]string{
					store.FileNameAnnotation:   d.Name(),
					store.FileDigestAnnotation: layerDigest.Encoded(),
				}
				manifest := ocispec.Manifest{
					Versioned: specs.Versioned{SchemaVersion: 2},
					MediaType: ocispec.MediaTypeImageManifest,
					Config: ocispec.Descriptor{
						MediaType: ocispec.MediaTypeImageConfig,
						Digest:    configDigest,
						Size:      int64(len(configData)),
					},
					Layers: []ocispec.Descriptor{
						{
							MediaType: ocispec.MediaTypeImageLayerGzip,
							Size:      info.Size(),
							Digest:    layerDigest,
						},
					},
					Annotations: annotations,
				}

				manifestData, err := json.MarshalIndent(manifest, "", "  ")
				if err != nil {
					log.Printf("Failed to marshal manifest for %s: %v", d.Name(), err)
					return nil
				}

				manifestDigest := digest.FromBytes(manifestData)
				manifestPath := filepath.Join(blobsDir, manifestDigest.Encoded())
				if err := os.WriteFile(manifestPath, manifestData, os.ModePerm); err != nil {
					log.Printf("Failed to write manifest file %s: %v", manifestPath, err)
					return nil
				}

				entry := ocispec.Descriptor{
					MediaType:   ocispec.MediaTypeImageManifest,
					Size:        int64(len(manifestData)),
					Digest:      manifestDigest,
					Annotations: annotations,

					Platform: &ocispec.Platform{
						OS:           osName,
						Architecture: arch,
					},
					ArtifactType: "application/vnd.tf.provider.v1+json",
				}
				// Add entry to the manifest list
				outerImageIndex.Manifests = append(outerImageIndex.Manifests, entry)
				innerImageIndex.Manifests = append(innerImageIndex.Manifests, entry)
			}

			return nil
		})

		if err != nil {
			log.Fatalf("Error walking the dist directory: %v", err)
		}

		innerIndexData, err := json.Marshal(innerImageIndex)
		if err != nil {
			log.Fatalf("Failed to marshal inner image index: %v", err)
		}

		innerIndexDigest := digest.FromBytes(innerIndexData)
		innerIndexPath := filepath.Join(blobsDir, innerIndexDigest.Encoded())
		if err := os.WriteFile(innerIndexPath, innerIndexData, os.ModePerm); err != nil {
			log.Fatalf("Failed to write manifest file %s: %v", innerIndexPath, err)
		}

		outerImageIndex.Manifests = append(outerImageIndex.Manifests, ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageIndex,
			Size:      int64(len(innerIndexData)),
			Digest:    innerIndexDigest,
			Annotations: map[string]string{
				ocispec.AnnotationRefName: refName,
			},
		})

		// Write the manifest list to index.json
		indexPath := filepath.Join(outPath, "index.json")
		indexFile, err := os.Create(indexPath)
		if err != nil {
			log.Fatalf("Failed to create index.json file: %v", err)
		}
		defer indexFile.Close()

		encoder := json.NewEncoder(indexFile)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(outerImageIndex); err != nil {
			log.Fatalf("Failed to write index.json: %v", err)
		}

		if !foundSig {
			log.Printf("No signature found")
		}
		if !foundShasum {
			log.Printf("No shasums found")
		}

		log.Printf("OCI layout created at %s", outPath)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVar(&refName, "ref-name", "", "Reference name for the OCI layout")
	generateCmd.Flags().StringVar(&inputPath, "input", "dist", "Input path for the zip files")
	generateCmd.Flags().StringVar(&outPath, "output", "oci-layout", "Output path for the tar.gz file")
	generateCmd.Flags().BoolVar(&cleanOutPath, "clean", false, "Clean the output path before generating")
}

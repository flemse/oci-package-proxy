package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	refName      string
	outPath      string
	cleanOutPath bool
)

type IndexFile struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []IndexEntry      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type IndexEntry struct {
	MediaType   string            `json:"mediaType"`
	Size        int64             `json:"size"`
	Digest      string            `json:"digest"`
	Platform    Platform          `json:"platform"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type LayerEntry struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}
type ManifestConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate OCI manifest list for zip files in the dist directory",
	Run: func(cmd *cobra.Command, args []string) {
		distDir := "dist"

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

		var imageIndex IndexFile
		imageIndex.SchemaVersion = 2
		imageIndex.MediaType = "application/vnd.oci.image.index.v1+json"

		//createdAt := time.Now().Format(time.RFC3339)
		err := filepath.WalkDir(distDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if d.IsDir() {
				return nil
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

				// Calculate SHA256 digest
				hash := sha256.New()
				if _, err := io.Copy(hash, file); err != nil {
					log.Printf("Failed to calculate digest for %s: %v", path, err)
					return nil
				}
				layerDigest := hex.EncodeToString(hash.Sum(nil))

				// Copy the file to blobs/sha256 with the digest as the filename
				blobPath := filepath.Join(blobsDir, layerDigest)
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
				configDigest := sha256.Sum256(configData)
				configDigestHex := hex.EncodeToString(configDigest[:])
				configPath := filepath.Join(blobsDir, configDigestHex)
				if err := os.WriteFile(configPath, configData, os.ModePerm); err != nil {
					log.Printf("Failed to write manifest file %s: %v", configPath, err)
					return nil
				}
				manifest := Manifest{
					SchemaVersion: 2,
					MediaType:     "application/vnd.oci.image.manifest.v1+json",
					Config: Descriptor{
						MediaType: "application/vnd.oci.image.config.v1+json",
						Digest:    "sha256:" + configDigestHex,
						Size:      int64(len(configData)),
					},
					Layers: []Descriptor{
						{
							MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
							Size:      info.Size(),
							Digest:    "sha256:" + layerDigest,
						},
					},
					Annotations: map[string]string{
						"org.opencontainers.image.original-filename": d.Name(),
					},
				}

				manifestData, err := json.MarshalIndent(manifest, "", "  ")
				if err != nil {
					log.Printf("Failed to marshal manifest for %s: %v", d.Name(), err)
					return nil
				}

				manifestDigest := sha256.Sum256(manifestData)
				manifestDigestHex := hex.EncodeToString(manifestDigest[:])
				manifestPath := filepath.Join(blobsDir, manifestDigestHex)
				if err := os.WriteFile(manifestPath, manifestData, os.ModePerm); err != nil {
					log.Printf("Failed to write manifest file %s: %v", manifestPath, err)
					return nil
				}
				// Add entry to the manifest list
				imageIndex.Manifests = append(imageIndex.Manifests, IndexEntry{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Size:      int64(len(manifestData)),
					Digest:    "sha256:" + manifestDigestHex,
					Platform: Platform{
						OS:           osName,
						Architecture: arch,
					},
					Annotations: map[string]string{
						"org.opencontainers.image.ref.name": fmt.Sprintf("%s-%s-%s", refName, osName, arch),
					},
				})
			}

			return nil
		})

		if err != nil {
			log.Fatalf("Error walking the dist directory: %v", err)
		}

		// Write the manifest list to index.json
		indexPath := filepath.Join(outPath, "index.json")
		indexFile, err := os.Create(indexPath)
		if err != nil {
			log.Fatalf("Failed to create index.json file: %v", err)
		}
		defer indexFile.Close()

		encoder := json.NewEncoder(indexFile)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(imageIndex); err != nil {
			log.Fatalf("Failed to write index.json: %v", err)
		}

		log.Printf("OCI layout created at %s", outPath)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVar(&refName, "ref-name", "", "Reference name for the OCI layout")
	generateCmd.Flags().StringVar(&outPath, "output", "oci-layout", "Output path for the tar.gz file")
	generateCmd.Flags().BoolVar(&cleanOutPath, "clean", false, "Clean the output path before generating")
}

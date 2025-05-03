package cmd

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	refName string
	outPath string
)

type IndexFile struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []IndexEntry `json:"manifests"`
}

type IndexEntry struct {
	MediaType   string            `json:"mediaType"`
	Size        int64             `json:"size"`
	Digest      string            `json:"digest"`
	Platform    Platform          `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type LayerEntry struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Layers        []LayerEntry `json:"layers"`
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

		createdAt := time.Now().Format(time.RFC3339)
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

				manifest := Manifest{
					SchemaVersion: 2,
					MediaType:     "application/vnd.oci.image.manifest.v1+json",
					Layers: []LayerEntry{
						{
							MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
							Size:      info.Size(),
							Digest:    "sha256:" + layerDigest,
						},
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
						"org.opencontainers.image.original-filename": d.Name(),
						"org.opencontainers.image.created":           createdAt,
						"org.opencontainers.image.ref.name":          refName,
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

		if err := createTar(outPath, outPath+".tar"); err != nil {
			log.Fatalf("Failed to create tar.gz: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVar(&refName, "ref-name", "", "Reference name for the OCI layout")
	generateCmd.Flags().StringVar(&outPath, "output", "oci-layout", "Output path for the tar.gz file")
}

func createTar(sourceDir, outputTarGz string) error {
	// Create the output tar.gz file
	outFile, err := os.Create(outputTarGz)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Create a tar writer
	tarWriter := tar.NewWriter(outFile)
	defer tarWriter.Close()

	// Walk through the source directory
	err = filepath.Walk(sourceDir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get the relative path
		relPath, err := filepath.Rel(sourceDir, file)
		if err != nil {
			return err
		}

		// Skip the root directory
		if relPath == "." {
			return nil
		}

		// Create a tar header
		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return err
		}
		header.Name = relPath

		// Write the header to the tar archive
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// If it's a file, write its content
		if !fi.IsDir() {
			fileContent, err := os.Open(file)
			if err != nil {
				return err
			}
			defer fileContent.Close()

			if _, err := io.Copy(tarWriter, fileContent); err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

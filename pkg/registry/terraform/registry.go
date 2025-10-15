package terraform

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strings"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/core"
	"github.com/flemse/oci-package-proxy/pkg/registry/terraform/auth"
	"github.com/flemse/oci-package-proxy/pkg/store"
	"github.com/go-chi/chi/v5"
)

type DiscoveryResponse struct {
	ModulesV1   string `json:"modules.v1"`
	ProvidersV1 string `json:"providers.v1"`
}

type VersionsResponse struct {
	Versions []VersionDetail `json:"versions"`
}

type VersionDetail struct {
	Version   string   `json:"version"`
	Protocols []string `json:"protocols"`
}

type Module struct {
	Name    string   `json:"name"`
	Version []string `json:"versions"`
}

type Provider struct {
	Name    string   `json:"name"`
	Version []string `json:"versions"`
}

type DownloadResponse struct {
	Arch                string                `json:"arch"`
	DownloadURL         string                `json:"download_url"`
	Filename            string                `json:"filename"`
	OS                  string                `json:"os"`
	Protocols           []string              `json:"protocols"`
	Shasum              string                `json:"shasum,omitempty"`
	ShasumsURL          string                `json:"shasums_url,omitempty"`
	ShasumsSignatureURL string                `json:"shasums_signature_url,omitempty"`
	SigningKeys         config.SigningKeyList `json:"signing_keys"`
}

type Registry struct {
	HostConfig  *config.HostConfig
	OrgKey      string
	PackageList *config.PackageList
	key         []byte
	creds       *core.CredsFetcher
}

func NewRegistry(hostConfig *config.HostConfig, packageList *config.PackageList) *Registry {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("failed to generate random key: %v", err)
	}

	return &Registry{
		HostConfig:  hostConfig,
		PackageList: packageList,
		key:         key,
		creds:       &core.CredsFetcher{EncryptionKey: key},
	}
}

func (re *Registry) SetupRoutes(mux chi.Router) {
	mux.HandleFunc("/v1/providers/{namespace}/{type}/versions", re.providerVersions)
	mux.HandleFunc("/v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}", re.providerDownload)
	mux.HandleFunc("/v1/modules/{namespace}/{name}/{system}/versions", re.moduleVersions)
	mux.HandleFunc("/v1/modules/{namespace}/{name}/{system}/{version}/download", re.moduleDownload)
	mux.HandleFunc("/_providers/{namespace}/{type}/{version}/{os}/{arch}/shasum", re.providerShasum)
	mux.HandleFunc("/_providers/{namespace}/{type}/{version}/{os}/{arch}/shasum.sig", re.providerShasumSig)
	mux.HandleFunc("/_providers/{namespace}/{type}/{version}/{os}/{arch}/stream", re.providerStream) // New route
	mux.HandleFunc("/_modules/{namespace}/{name}/{system}/{version}/stream", re.moduleStream)        // New route
	mux.HandleFunc("/v1/login", re.HandleLogin)
	mux.HandleFunc("/.well-known/terraform.json", re.HandleWellKnownTerraform)
	mux.HandleFunc("/terraform/upload", re.HandleUpload)
}

func (re *Registry) providerShasum(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	creds := re.creds.FromRequest(r)

	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	shasums, err := ociStore.Shasums(r.Context(), "v"+version)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/text")
	w.Write(shasums)
}

func (re *Registry) providerShasumSig(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	creds := re.creds.FromRequest(r)

	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	sig, err := ociStore.GetSignature(r.Context(), "v"+version)
	if err != nil {
		log.Printf("Error getting signature: %v", err)
		http.Error(w, "Error getting signature", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(sig)
}

func (re *Registry) moduleStream(w http.ResponseWriter, r *http.Request) {
	//ns := r.PathValue("namespace")
	//name := r.PathValue("name")
	//system := r.PathValue("system")
	version := r.PathValue("version")
	creds := re.creds.FromRequest(r)

	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	content, err := ociStore.GetFileContent(r.Context(), "v"+version, "", "")
	if err != nil {
		log.Printf("Error getting file content: %v", err)
		http.Error(w, "Error getting file content", http.StatusInternalServerError)
		return
	}
	defer content.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=terraform-provider_%s_%s.zip", "", ""))

	buf := make([]byte, 32*1024) // 32KB buffer
	written, err := io.CopyBuffer(w, content, buf)
	if err != nil {
		log.Printf("Error writing file content: %v", err)
		// We can't send an HTTP error here as headers have already been sent
		if written > 0 {
			log.Printf("Partial write: %d bytes written before error", written)
		}
		// Don't exit the handler until copy is complete or fails
		return
	}
}

func (re *Registry) providerStream(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	osName := r.PathValue("os")
	arch := r.PathValue("arch")
	creds := re.creds.FromRequest(r)

	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	content, err := ociStore.GetFileContent(r.Context(), "v"+version, osName, arch)
	if err != nil {
		log.Printf("Error getting file content: %v", err)
		http.Error(w, "Error getting file content", http.StatusInternalServerError)
		return
	}
	defer content.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=terraform-provider_%s_%s.zip", osName, arch))

	buf := make([]byte, 32*1024) // 32KB buffer
	written, err := io.CopyBuffer(w, content, buf)
	if err != nil {
		log.Printf("Error writing file content: %v", err)
		// We can't send an HTTP error here as headers have already been sent
		if written > 0 {
			log.Printf("Partial write: %d bytes written before error", written)
		}
		// Don't exit the handler until copy is complete or fails
		return
	}
}

func (re *Registry) providerDownload(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("namespace")
	t := r.PathValue("type")
	version := r.PathValue("version")
	osName := r.PathValue("os")
	arch := r.PathValue("arch")
	creds := re.creds.FromRequest(r)

	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	token := ""
	if creds != nil {
		t, err := auth.Encrypt(re.key, creds.Password, core.GenerateFingerprint(r))
		if err != nil {
			log.Printf("Error encrypting token: %v", err)
			http.Error(w, "Error encrypting token", http.StatusInternalServerError)
			return
		}
		token = t
	}

	info, err := ociStore.DownloadUrlForPlatform(r.Context(), "v"+version, osName, arch)
	if err != nil {
		log.Printf("Error getting download URL: %v", err)
		http.Error(w, "Error getting download URL", http.StatusInternalServerError)
		return
	}
	keys := config.SigningKeyList{GPGPublicKeys: []*config.SigningKey{}}

	for _, p := range re.PackageList.Packages {
		if p.Name == ns+"/"+t {
			keys.GPGPublicKeys = p.SigningKeys
			break
		}
	}

	downloadURL := "/_providers/" + ns + "/" + t + "/" + version + "/" + osName + "/" + arch + "/stream"
	if token != "" {
		downloadURL += "?token=" + token
	}

	resp := DownloadResponse{
		Arch:                arch,
		DownloadURL:         downloadURL,
		Filename:            info.Filename,
		OS:                  osName,
		Protocols:           []string{"5.0"},
		Shasum:              info.Digest,
		ShasumsURL:          "/_providers/" + ns + "/" + t + "/" + version + "/" + osName + "/" + arch + "/shasum",
		ShasumsSignatureURL: "/_providers/" + ns + "/" + t + "/" + version + "/" + osName + "/" + arch + "/shasum.sig",
		SigningKeys:         keys,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (re *Registry) providerVersions(w http.ResponseWriter, r *http.Request) {
	creds := re.creds.FromRequest(r)
	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	versions, err := ociStore.Versions(r.Context())
	if err != nil {
		log.Printf("Error getting versions: %v", err)
		http.Error(w, "Error getting versions", http.StatusInternalServerError)
		return
	}

	var response VersionsResponse
	for _, v := range versions {
		response.Versions = append(response.Versions, VersionDetail{
			Version:   v,
			Protocols: []string{"5.0"}, // Example protocol version
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (re *Registry) moduleDownload(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("namespace")
	name := r.PathValue("name")
	system := r.PathValue("system")
	version := r.PathValue("version")
	creds := re.creds.FromRequest(r)

	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	token := ""
	if creds != nil {
		t, err := auth.Encrypt(re.key, creds.Password, core.GenerateFingerprint(r))
		if err != nil {
			log.Printf("Error encrypting token: %v", err)
			http.Error(w, "Error encrypting token", http.StatusInternalServerError)
			return
		}
		token = t
	}

	_, err = ociStore.DownloadUrlForPlatform(r.Context(), "v"+version, "", "")
	if err != nil {
		log.Printf("Error getting download URL: %v", err)
		http.Error(w, "Error getting download URL", http.StatusInternalServerError)
		return
	}

	downloadURL := fmt.Sprintf("/_modules/%s/%s/%s/%s/stream", ns, name, system, version)
	if token != "" {
		downloadURL += "?token=" + token
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Terraform-Get", downloadURL)
	w.WriteHeader(http.StatusNoContent)
}

func (re *Registry) moduleVersions(w http.ResponseWriter, r *http.Request) {
	creds := re.creds.FromRequest(r)
	ociStore, err := store.NewStore(re.HostConfig, re.packageName(r), creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	versions, err := ociStore.Versions(r.Context())
	if err != nil {
		log.Printf("Error getting versions: %v", err)
		http.Error(w, "Error getting versions", http.StatusInternalServerError)
		return
	}

	var response VersionsResponse
	for _, v := range versions {
		response.Versions = append(response.Versions, VersionDetail{
			Version:   v,
			Protocols: []string{"5.0"}, // Example protocol version
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (re *Registry) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Replace with proper authentication logic
	if username == "admin" && password == "password" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Login successful"))
		return
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

func (re *Registry) HandleWellKnownTerraform(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	discovery := DiscoveryResponse{
		ModulesV1:   "/v1/modules/",
		ProvidersV1: "/v1/providers/",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (re *Registry) packageName(r *http.Request) string {
	var segments []string
	if re.OrgKey != "" {
		segments = append(segments, re.OrgKey)
	}
	segments = append(segments,
		r.PathValue("namespace"),
		r.PathValue("type"))

	return path.Join(segments...)
}

// HandleUpload handles the upload of Terraform provider packages
func (re *Registry) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 100MB)
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get required form values
	namespace := r.FormValue("namespace")
	providerType := r.FormValue("type")
	version := r.FormValue("version")

	if namespace == "" || providerType == "" || version == "" {
		http.Error(w, "Missing required fields: namespace, type, or version", http.StatusBadRequest)
		return
	}

	// Get SHA256SUMS file
	shasumsFile, _, err := r.FormFile("SHA256SUMS")
	if err != nil {
		log.Printf("Error getting SHA256SUMS file: %v", err)
		http.Error(w, "SHA256SUMS file is required", http.StatusBadRequest)
		return
	}
	defer shasumsFile.Close()

	shasumsContent, err := io.ReadAll(shasumsFile)
	if err != nil {
		log.Printf("Error reading SHA256SUMS: %v", err)
		http.Error(w, "Error reading SHA256SUMS", http.StatusInternalServerError)
		return
	}

	// Get optional signature file
	var signatureContent []byte
	sigFile, _, err := r.FormFile("SHA256SUMS.sig")
	if err == nil {
		defer sigFile.Close()
		signatureContent, err = io.ReadAll(sigFile)
		if err != nil {
			log.Printf("Error reading signature: %v", err)
			http.Error(w, "Error reading signature", http.StatusInternalServerError)
			return
		}
	}

	// Parse SHA256SUMS to get expected files
	expectedFiles := parseSHA256SUMS(string(shasumsContent))
	if len(expectedFiles) == 0 {
		http.Error(w, "No files found in SHA256SUMS", http.StatusBadRequest)
		return
	}

	// Collect provider files
	var providerFiles []store.ProviderFile
	for filename := range expectedFiles {
		file, header, err := r.FormFile(filename)
		if err != nil {
			log.Printf("Missing required file: %s", filename)
			http.Error(w, fmt.Sprintf("Missing required file: %s", filename), http.StatusBadRequest)
			return
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			log.Printf("Error reading file %s: %v", filename, err)
			http.Error(w, fmt.Sprintf("Error reading file: %s", filename), http.StatusInternalServerError)
			return
		}

		// Verify checksum
		actualChecksum := fmt.Sprintf("%x", store.SHA256Sum(content))
		if actualChecksum != expectedFiles[filename] {
			log.Printf("Checksum mismatch for %s: expected %s, got %s", filename, expectedFiles[filename], actualChecksum)
			http.Error(w, fmt.Sprintf("Checksum mismatch for file: %s", filename), http.StatusBadRequest)
			return
		}

		// Extract OS and architecture from filename
		// Expected format: provider_version_os_arch.zip
		osName, arch := extractPlatformFromFilename(header.Filename)

		providerFiles = append(providerFiles, store.ProviderFile{
			Name:    header.Filename,
			Content: content,
			OS:      osName,
			Arch:    arch,
		})
	}

	// Create OCI store
	packageName := path.Join(namespace, providerType)
	if re.OrgKey != "" {
		packageName = path.Join(re.OrgKey, packageName)
	}

	creds := re.creds.FromRequest(r)
	ociStore, err := store.NewStore(re.HostConfig, packageName, creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	// Push provider bundle to OCI registry
	tag := "v" + version
	if err := ociStore.PushProviderBundle(r.Context(), tag, providerFiles, shasumsContent, signatureContent); err != nil {
		log.Printf("Error pushing provider bundle: %v", err)
		http.Error(w, "Error pushing provider bundle", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"message":   "Provider uploaded successfully",
		"namespace": namespace,
		"type":      providerType,
		"version":   version,
		"tag":       tag,
	})
}

// parseSHA256SUMS parses the SHA256SUMS file and returns a map of filename to checksum
func parseSHA256SUMS(content string) map[string]string {
	files := make(map[string]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: checksum  filename
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			checksum := parts[0]
			filename := parts[1]

			// Only include .zip files (skip .sbom.json and manifest.json files for now)
			if strings.HasSuffix(filename, ".zip") {
				files[filename] = checksum
			}
		}
	}

	return files
}

// extractPlatformFromFilename extracts OS and architecture from filename
// Expected format: name_version_os_arch.zip
func extractPlatformFromFilename(filename string) (string, string) {
	// Remove .zip extension
	name := strings.TrimSuffix(filename, ".zip")

	// Split by underscore
	parts := strings.Split(name, "_")

	if len(parts) >= 2 {
		// Last part is architecture, second to last is OS
		arch := parts[len(parts)-1]
		osName := parts[len(parts)-2]
		return osName, arch
	}

	return "", ""
}

package terraform

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/core"
	"github.com/flemse/oci-package-proxy/pkg/registries/terraform/auth"
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

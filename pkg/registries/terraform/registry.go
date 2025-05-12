package terraform

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

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
	Arch                string         `json:"arch"`
	DownloadURL         string         `json:"download_url"`
	Filename            string         `json:"filename"`
	OS                  string         `json:"os"`
	Protocols           []string       `json:"protocols"`
	Shasum              string         `json:"shasum,omitempty"`
	ShasumsURL          string         `json:"shasums_url,omitempty"`
	ShasumsSignatureURL string         `json:"shasums_signature_url,omitempty"`
	SigningKeys         SigningKeyList `json:"signing_keys"`
}

var (
	Modules   []Module
	Providers = []Provider{
		{Name: "novus/applicationmanagement", Version: []string{"0.3.0"}},
	}
)

type Registry struct {
	OCI         *store.Store
	PackageList *PackageList
}

func (re *Registry) SetupRoutes(mux chi.Router) {
	mux.HandleFunc("/v1/modules/", re.HandleModules)
	mux.HandleFunc("/v1/providers/{namespace}/{type}", re.providerBase)
	mux.HandleFunc("/v1/providers/{namespace}/{type}/versions", re.providerVersions)
	mux.HandleFunc("/v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}", re.providerDownload)
	mux.HandleFunc("/_providers/{namespace}/{type}/{version}/{os}/{arch}/shasum", re.providerShasum)
	mux.HandleFunc("/_providers/{namespace}/{type}/{version}/{os}/{arch}/shasum.sig", re.providerShasumSig)
	mux.HandleFunc("/_providers/{namespace}/{type}/{version}/{os}/{arch}/stream", re.providerStream) // New route
	mux.HandleFunc("/v1/login", re.HandleLogin)
	mux.HandleFunc("/.well-known/terraform.json", re.HandleWellKnownTerraform)
}

func (re *Registry) HandleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	moduleName := r.URL.Path[len("/v1/modules/"):]
	for _, module := range Modules {
		if module.Name == moduleName {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(module)
			return
		}
	}

	http.Error(w, "Module not found", http.StatusNotFound)
}

func (re *Registry) providerBase(w http.ResponseWriter, r *http.Request) {
	// Handle metadata: /v1/providers/:namespace/:type
	ns := r.PathValue("namespace")
	t := r.PathValue("type")
	for _, provider := range Providers {
		if provider.Name == ns+"/"+t {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(provider)
			return
		}
	}
	http.Error(w, "Provider not found", http.StatusNotFound)
	return
}

func (re *Registry) providerShasum(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")

	shasums, err := re.OCI.Shasums(r.Context(), "v"+version)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/text")
	w.Write(shasums)
}

func (re *Registry) providerShasumSig(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")

	sig, err := re.OCI.GetSignature(r.Context(), "v"+version)
	if err != nil {
		log.Printf("Error getting signature: %v", err)
		http.Error(w, "Error getting signature", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(sig)
}

func (re *Registry) providerStream(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	osName := r.PathValue("os")
	arch := r.PathValue("arch")

	content, err := re.OCI.GetFileContent(r.Context(), "v"+version, osName, arch)
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

	info, err := re.OCI.DownloadUrlForPlatform(r.Context(), "v"+version, osName, arch)
	if err != nil {
		log.Printf("Error getting download URL: %v", err)
		http.Error(w, "Error getting download URL", http.StatusInternalServerError)
		return
	}
	keys := SigningKeyList{GPGPublicKeys: []*SigningKey{}}

	for _, p := range re.PackageList.Packages {
		if p.Name == ns+"/"+t {
			keys.GPGPublicKeys = p.SigningKeys
			break
		}
	}

	resp := DownloadResponse{
		Arch:                arch,
		DownloadURL:         "/_providers/" + ns + "/" + t + "/" + version + "/" + osName + "/" + arch + "/stream",
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
	//ns := r.PathValue("namespace")
	//t := r.PathValue("type")
	versions, err := re.OCI.Versions(r.Context())
	if err != nil {
		log.Printf("Error getting versions: %v", err)
		http.Error(w, "Error getting versions", http.StatusInternalServerError)
		return
	}
	// Handle versions: /v1/providers/:namespace/:type/versions
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

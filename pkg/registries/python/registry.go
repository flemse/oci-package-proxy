package python

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/core"
	"github.com/flemse/oci-package-proxy/pkg/store"
	"github.com/go-chi/chi/v5"
)

type Registry struct {
	HostConfig  *config.HostConfig
	PackageList *config.PackageList
	creds       *core.CredsFetcher
}

func NewRegistry(hostConfig *config.HostConfig, packageList *config.PackageList) *Registry {
	return &Registry{
		HostConfig:  hostConfig,
		PackageList: packageList,
		creds:       &core.CredsFetcher{},
	}
}

func (re *Registry) SetupRoutes(mux chi.Router) {
	mux.Get("/simple/{package}/", re.handleSimpleIndex)
	mux.Get("/packages/{filename}", re.handlePackageDownload)
	mux.Post("/upload/", re.handlePackageUpload)
}

func (re *Registry) handleSimpleIndex(w http.ResponseWriter, r *http.Request) {
	// Build a list of all Python packages from the PackageList
	var pythonPackages []string
	if re.PackageList != nil {
		for _, pkg := range re.PackageList.Packages {
			if pkg.Type == config.PackageTypePython {
				pythonPackages = append(pythonPackages, pkg.Name)
			}
		}
	}

	// Return PyPI simple index HTML listing all Python packages
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<!DOCTYPE html>\n<html>\n<body>\n"))
	for _, pkgName := range pythonPackages {
		w.Write([]byte("<a href='/simple/" + pkgName + "/'>" + pkgName + "</a><br/>\n"))
	}
	w.Write([]byte("</body>\n</html>"))
}

func (re *Registry) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")
	creds := re.creds.FromRequest(r)
	ociStore, err := store.NewStore(re.HostConfig, filename, creds)
	if err != nil {
		log.Printf("Error creating OCI store: %v", err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}
	content, err := ociStore.GetFileContent(r.Context(), "latest", "", "")
	if err != nil {
		log.Printf("Error getting file content: %v", err)
		http.Error(w, "Error getting file content", http.StatusInternalServerError)
		return
	}
	defer content.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	io.Copy(w, content)
}

func (re *Registry) handlePackageUpload(w http.ResponseWriter, r *http.Request) {
	creds := re.creds.FromRequest(r)
	if err := r.ParseMultipartForm(100 << 20); err != nil { // 100MB max
		http.Error(w, "failed to parse multipart form", http.StatusBadRequest)
		return
	}
	print(creds)
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer file.Close()
	filename := handler.Filename
	// Save to temp file
	tmpPath := filepath.Join(os.TempDir(), filename)
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer tmpFile.Close()
	if _, err := io.Copy(tmpFile, file); err != nil {
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("OK"))
}

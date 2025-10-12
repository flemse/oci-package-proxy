package python

import (
	"io"
	"log"
	"net/http"

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
	mux.Get("/simple/{package}", re.handleSimpleIndex)
	mux.Get("/simple", re.handleSimpleIndexRoot)
	mux.Get("/packages/{filename}", re.handlePackageDownload)
	mux.Post("/upload/", re.handlePackageUpload)
}

func (re *Registry) handleSimpleIndex(w http.ResponseWriter, r *http.Request) {
	packageName := r.PathValue("package")

	// Check if the package exists in the PackageList
	var packageExists bool
	if re.PackageList != nil {
		for _, pkg := range re.PackageList.Packages {
			if pkg.Type == config.PackageTypePython && pkg.Name == packageName {
				packageExists = true
				break
			}
		}
	}

	if !packageExists {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	// Get credentials and create OCI store
	creds := re.creds.FromRequest(r)
	ociStore, err := store.NewStore(re.HostConfig, packageName, creds)
	if err != nil {
		log.Printf("Error creating OCI store for package %s: %v", packageName, err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	// Get all versions/tags for this package
	versions, err := ociStore.Versions(r.Context())
	if err != nil {
		log.Printf("Error fetching versions for package %s: %v", packageName, err)
		http.Error(w, "Error fetching package versions", http.StatusInternalServerError)
		return
	}

	// Build list of all download URLs for all versions
	var downloadLinks []struct {
		Filename string
		URL      string
	}

	for _, version := range versions {
		urls, err := ociStore.DownloadUrls(r.Context(), version)
		if err != nil {
			log.Printf("Warning: Could not fetch download URLs for version %s: %v", version, err)
			continue
		}

		for filename, url := range urls {
			downloadLinks = append(downloadLinks, struct {
				Filename string
				URL      string
			}{
				Filename: filename,
				URL:      url,
			})
		}
	}

	// Return PyPI simple index HTML for this package
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<!DOCTYPE html>\n<html>\n<head>\n<title>Links for " + packageName + "</title>\n</head>\n<body>\n<h1>Links for " + packageName + "</h1>\n"))

	for _, link := range downloadLinks {
		w.Write([]byte("<a href='" + link.URL + "'>" + link.Filename + "</a><br/>\n"))
	}

	w.Write([]byte("</body>\n</html>"))
}

func (re *Registry) handleSimpleIndexRoot(w http.ResponseWriter, r *http.Request) {
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

	// Twine sends the file in the "content" field, not "file"
	file, handler, err := r.FormFile("content")
	if err != nil {
		// Fallback to "file" field for other clients
		file, handler, err = r.FormFile("file")
		if err != nil {
			log.Printf("Error: missing file field in upload request. Available fields: %v", r.MultipartForm.File)
			http.Error(w, "missing content or file field", http.StatusBadRequest)
			return
		}
	}
	defer file.Close()

	filename := handler.Filename

	// Extract package name and version from form data
	// Twine sends these as "name" and "version" fields
	packageName := r.FormValue("name")
	version := r.FormValue("version")

	// Log all form values for debugging
	log.Printf("Upload request - name: %s, version: %s, filename: %s", packageName, version, filename)

	if packageName == "" {
		log.Printf("Error: missing package name in upload request. Available form values: %v", r.Form)
		http.Error(w, "missing package name", http.StatusBadRequest)

		return
	}

	if version == "" {
		log.Printf("Warning: missing version in upload request, using 'latest'")
		http.Error(w, "missing version in upload request", http.StatusBadRequest)

		return
	}

	// Create OCI store for this package
	ociStore, err := store.NewStore(re.HostConfig, packageName, creds)
	if err != nil {
		log.Printf("Error creating OCI store for package %s: %v", packageName, err)
		http.Error(w, "failed to create OCI store", http.StatusInternalServerError)
		return
	}

	// Push the file to the OCI registry
	if err := ociStore.PushFile(r.Context(), file, filename, version); err != nil {
		log.Printf("Error pushing file %s to OCI store: %v", filename, err)
		http.Error(w, "failed to upload package to registry", http.StatusInternalServerError)

		return
	}

	log.Printf("Successfully uploaded package %s version %s (file: %s)", packageName, version, filename)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("OK"))
}

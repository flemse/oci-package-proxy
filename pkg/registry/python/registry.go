package python

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/flemse/oci-package-proxy/pkg/config"
	"github.com/flemse/oci-package-proxy/pkg/core"
	"github.com/flemse/oci-package-proxy/pkg/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// normalizePackageName normalizes a Python package name according to PEP 503
// It converts to lowercase and replaces runs of [-_.] with a single dash
func normalizePackageName(name string) string { // todo: remove this crap, we should be standard compliant when parsing the package list, not retroactively!
	name = strings.ToLower(name)
	re := regexp.MustCompile(`[-_.]+`)
	return re.ReplaceAllString(name, "-")
}

// Template for the simple package index page
var simpleIndexTemplate = template.Must(template.New("simpleIndex").Parse(`<!DOCTYPE html>
<html>
<head>
<title>Links for {{.PackageName}}</title>
</head>
<body>
<h1>Links for {{.PackageName}}</h1>
{{range .Links}}
<a href="{{.URL}}">{{.Filename}}</a><br/>
{{end}}
</body>
</html>`))

// Template for the simple index root page
var simpleIndexRootTemplate = template.Must(template.New("simpleIndexRoot").Parse(`<!DOCTYPE html>
<html>
<body>
{{range .Packages}}
<a href="/simple/{{.}}/">{{.}}</a><br/>
{{end}}
</body>
</html>`))

type DownloadLink struct {
	Filename string
	URL      string
}

type simpleIndexData struct {
	PackageName string
	Links       []DownloadLink
}

type simpleIndexRootData struct {
	Packages []string
}

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

func (re *Registry) SetupRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(middleware.StripSlashes)
		r.Get("/simple/{package}/", re.handleSimpleIndex)
		r.Get("/simple/", re.handleSimpleIndexRoot)
		r.Get("/packages/{filename}", re.handlePackageDownload)
		r.Post("/upload/", re.handlePackageUpload)
	})
}

func (re *Registry) handleSimpleIndex(w http.ResponseWriter, r *http.Request) {
	packageName := r.PathValue("package")
	normalizedRequestName := normalizePackageName(packageName)

	// Check if the package exists in the PackageList (using normalized names for comparison)
	var packageExists bool
	var actualPackageName string
	if re.PackageList != nil {
		for _, pkg := range re.PackageList.Packages {
			if pkg.Type == config.PackageTypePython && normalizePackageName(pkg.Name) == normalizedRequestName {
				packageExists = true
				actualPackageName = pkg.Name
				break
			}
		}
	}

	if !packageExists {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	// Get credentials and create OCI store using the actual package name from config
	creds := re.creds.FromRequest(r)
	ociStore, err := store.NewStore(re.HostConfig, actualPackageName, creds)
	if err != nil {
		log.Printf("Error creating OCI store for package %s: %v", actualPackageName, err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	// Get all versions/tags for this package
	versions, err := ociStore.Versions(r.Context())
	if err != nil {
		// If the repository doesn't exist yet (404), return an empty package list
		// This is normal for packages that haven't been uploaded yet
		log.Printf("Warning: Could not fetch versions for package %s: %v (returning empty list)", actualPackageName, err)
		versions = []string{}
	}

	// Build the base URL for absolute links (required for proper pip resolution)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	baseURL := scheme + "://" + r.Host

	// Build list of all download URLs for all versions
	// Point to /packages/{filename} endpoint instead of direct OCI URLs
	var downloadLinks []DownloadLink

	for _, version := range versions {
		urls, err := ociStore.DownloadUrls(r.Context(), version)
		if err != nil {
			log.Printf("Warning: Could not fetch download URLs for version %s: %v", version, err)
			continue
		}

		for filename := range urls {
			// Use absolute URL for package download
			downloadLinks = append(downloadLinks, DownloadLink{
				Filename: filename,
				URL:      baseURL + "/packages/" + filename,
			})
		}
	}

	// Return PyPI simple index HTML for this package
	w.Header().Set("Content-Type", "text/html")

	data := simpleIndexData{
		PackageName: packageName,
		Links:       downloadLinks,
	}

	if err := simpleIndexTemplate.Execute(w, data); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
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

	data := simpleIndexRootData{
		Packages: pythonPackages,
	}

	if err := simpleIndexRootTemplate.Execute(w, data); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func (re *Registry) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")

	// Extract package name from filename
	// Python wheel format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
	// Source dist format: {name}-{version}.tar.gz or .zip

	// Find the package in our PackageList by matching normalized names
	var packageName string
	var found bool

	if re.PackageList != nil {
		for _, pkg := range re.PackageList.Packages {
			if pkg.Type == config.PackageTypePython {
				// Check if the filename starts with the normalized package name
				normalizedPkg := normalizePackageName(pkg.Name)
				normalizedFilename := normalizePackageName(filename)
				if strings.HasPrefix(normalizedFilename, normalizedPkg+"-") {
					packageName = pkg.Name
					found = true
					break
				}
			}
		}
	}

	if !found {
		log.Printf("Error: could not determine package name from filename: %s", filename)
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	creds := re.creds.FromRequest(r)
	ociStore, err := store.NewStore(re.HostConfig, packageName, creds)
	if err != nil {
		log.Printf("Error creating OCI store for package %s: %v", packageName, err)
		http.Error(w, "Error creating OCI store", http.StatusInternalServerError)
		return
	}

	// Get all versions and find the one containing this file
	versions, err := ociStore.Versions(r.Context())
	if err != nil {
		log.Printf("Error fetching versions for package %s: %v", packageName, err)
		http.Error(w, "Error fetching package versions", http.StatusInternalServerError)
		return
	}

	// Search through all versions to find the one containing this file
	var fileVersion string
	for _, version := range versions {
		urls, err := ociStore.DownloadUrls(r.Context(), version)
		if err != nil {
			log.Printf("Warning: Could not fetch download URLs for version %s: %v", version, err)
			continue
		}

		// Check if this version has the requested file
		if _, exists := urls[filename]; exists {
			fileVersion = version
			break
		}
	}

	if fileVersion == "" {
		log.Printf("Error: file %s not found in any version of package %s", filename, packageName)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Stream the file content from OCI registry
	content, err := ociStore.GetFileContent(r.Context(), fileVersion, "", "")
	if err != nil {
		log.Printf("Error getting file content: %v", err)
		http.Error(w, "Error getting file content", http.StatusInternalServerError)
		return
	}
	defer content.Close()

	// Set appropriate headers for Python package download
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)

	// Stream the content using a buffer like providerStream
	buf := make([]byte, 32*1024) // 32KB buffer
	written, err := io.CopyBuffer(w, content, buf)
	if err != nil {
		log.Printf("Error writing file content: %v", err)
		// We can't send an HTTP error here as headers have already been sent
		if written > 0 {
			log.Printf("Partial write: %d bytes written before error", written)
		}
		return
	}

	log.Printf("Successfully streamed package file %s (%d bytes)", filename, written)
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

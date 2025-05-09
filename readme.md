# OCI Package Proxy

This application will help converting various package types like terraform providers into OCI artifacts.

```bash
# Install CLI for interactions
brew install oras

# Setup the registry
docker run -d --rm -p 5001:5000 --name tf-oci ghcr.io/project-zot/zot:latest
```

## Examples

```bash
# Prepare oci layout from an existing provider dist
go run . generate --ref-name v0.3.0 --input /path/to/provider/dist --output tmp/dist --clean

# Push to registry
oras cp --from-oci-layout ./tmp/dist:v0.3.0 localhost:5001/package/name:v0.3.0

# start proxy with local registry
go run . registry --oci-host localhost:5001 --oci-insecure

# start proxy with remote registry
GITHUB_TOKEN=token go run . registry --repo-name lego/novus/applicationmanagement
```
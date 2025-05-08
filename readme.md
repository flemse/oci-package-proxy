# OCI Package Proxy

This application will help converting various package types like terraform providers into OCI artifacts.

```bash
# Install CLI for interactions
brew install oras

# Setup the registry
docker run -d --rm -p 5001:5000 --name tf-oci ghcr.io/project-zot/zot:latest

docker run -it --rm \
  -p 5001:5000 \
  --name tf-oci \
  -v $(pwd)/tmp/cert.pem:/etc/ssl/certs/cert.pem:ro \
  -v $(pwd)/tmp/key.pem:/etc/ssl/private/key.pem:ro \
  -v $(pwd)/tmp/zot-config.json:/etc/zot/config.json:ro \
  ghcr.io/project-zot/zot:latest 
```

## Build multi arch image

```bash
docker build --pull --platform linux/arm64 -t localhost:5001/hello-world:v1-linux-arm64 .
docker build --pull --platform linux/amd64 -t localhost:5001/hello-world:v1-linux-amd64 .

docker push localhost:5001/hello-world:v1-linux-arm64
docker push localhost:5001/hello-world:v1-linux-amd64

docker manifest create --insecure localhost:5001/hello-world:v1 \
  localhost:5001/hello-world:v1-linux-arm64 \
  localhost:5001/hello-world:v1-linux-amd64
docker manifest push localhost:5001/hello-world:v1

# Prepare oci layout
go run . generate --ref-name v0.3.0 --input /path/to/provider/dist --output tmp/dist --clean

# Push to registry
oras cp --from-oci-layout ./tmp/dist:v0.3.0 localhost:5001/package/name:v0.3.0
```
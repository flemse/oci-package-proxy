# Test app

Flemming playground for all sort of things

```bash
# Install CLI for interactions
brew install oras

# Setup the registry
docker run -it --rm -p 5001:5000 --name tf-oci ghcr.io/project-zot/zot:latest
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
```
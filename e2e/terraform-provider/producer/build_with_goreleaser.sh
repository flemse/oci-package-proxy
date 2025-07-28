#!/bin/bash

# Build the Terraform provider code using GoReleaser in a Docker container
docker run --rm \
  -v $(pwd)/e2e/terraform-provider/producer:/app \
  -w /app \
  golang:1.24 \
  bash  -c "$(cat <<EOF
set -euo pipefail
go install github.com/goreleaser/goreleaser/v2@latest
goreleaser release --snapshot --clean
EOF
)"
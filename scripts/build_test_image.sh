#!/bin/bash

# Build the unified test container image
# This image includes Go, Terraform, Python, and GoReleaser pre-installed
# to significantly speed up test execution times.

set -e

echo "Building oci-package-proxy-test:latest..."
docker build -t oci-package-proxy-test:latest -f Dockerfile.test .

echo "✓ Test image built successfully!"
echo ""
echo "The image includes:"
echo "  - Go 1.25.1"
echo "  - Terraform 1.9.8"
echo "  - Python 3"
echo "  - GoReleaser v2"
echo "  - ca-certificates and other essential tools"
echo ""
echo "Run tests with: go test ./..."


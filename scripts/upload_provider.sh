#!/bin/bash

# Script to upload a Terraform provider package to the OCI registry
# Usage: ./upload_provider.sh <namespace> <type> <version> <dist-directory>

set -e

NAMESPACE=${1:-"hashicorp"}
TYPE=${2:-"sample-provider"}
VERSION=${3:-"0.0.0-SNAPSHOT-981ad9a"}
DIST_DIR=${4:-"pkg/registries/terraform/sample/dist"}

# Base URL of the registry
REGISTRY_URL=${REGISTRY_URL:-"http://localhost:8080"}

# Build the multipart form data
CURL_ARGS=()

# Add form fields
CURL_ARGS+=(-F "namespace=${NAMESPACE}")
CURL_ARGS+=(-F "type=${TYPE}")
CURL_ARGS+=(-F "version=${VERSION}")

# Add SHA256SUMS file
if [ -f "${DIST_DIR}/${TYPE}_${VERSION}_SHA256SUMS" ]; then
    CURL_ARGS+=(-F "SHA256SUMS=@${DIST_DIR}/${TYPE}_${VERSION}_SHA256SUMS")
else
    echo "Error: SHA256SUMS file not found at ${DIST_DIR}/${TYPE}_${VERSION}_SHA256SUMS"
    exit 1
fi

# Add optional signature file
if [ -f "${DIST_DIR}/${TYPE}_${VERSION}_SHA256SUMS.sig" ]; then
    CURL_ARGS+=(-F "SHA256SUMS.sig=@${DIST_DIR}/${TYPE}_${VERSION}_SHA256SUMS.sig")
fi

# Parse SHA256SUMS and add all .zip files
while IFS= read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    # Extract filename (second field)
    filename=$(echo "$line" | awk '{print $2}')

    # Only process .zip files
    if [[ "$filename" == *.zip ]]; then
        filepath="${DIST_DIR}/${filename}"
        if [ -f "$filepath" ]; then
            echo "Adding file: $filename"
            CURL_ARGS+=(-F "${filename}=@${filepath}")
        else
            echo "Warning: File not found: $filepath"
        fi
    fi
done < "${DIST_DIR}/${TYPE}_${VERSION}_SHA256SUMS"

# Upload to registry
echo "Uploading provider to ${REGISTRY_URL}/terraform/upload"
curl -v "${CURL_ARGS[@]}" "${REGISTRY_URL}/terraform/upload"

echo ""
echo "Upload complete!"


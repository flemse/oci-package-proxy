# Terraform Provider Upload Endpoint

## Overview

The `/terraform/upload` endpoint allows you to upload Terraform provider packages to the OCI registry. It accepts a SHA256SUMS file along with all the provider zip files mentioned in it.

## Endpoint

**URL:** `/terraform/upload`  
**Method:** `POST`  
**Content-Type:** `multipart/form-data`

## Request Parameters

### Form Fields (required)
- `namespace` - The provider namespace (e.g., "hashicorp")
- `type` - The provider type (e.g., "aws", "google", "sample-provider")
- `version` - The provider version (e.g., "1.0.0")

### Form Files (required)
- `SHA256SUMS` - The SHA256SUMS file containing checksums for all provider files

### Form Files (optional)
- `SHA256SUMS.sig` - GPG signature file for the SHA256SUMS
- All `.zip` files mentioned in the SHA256SUMS file (must match the checksums)

## Example SHA256SUMS Format

```
d10c473de62576743cbcbbf4d97a4fc83be2525cc39e0c545cb8816fe13cce58  sample-provider_0.0.0-SNAPSHOT-981ad9a_darwin_amd64.zip
140ea361d8c4b7191153d65a297b8df858eab33ccde77e817053f85a228b1c4e  sample-provider_0.0.0-SNAPSHOT-981ad9a_darwin_arm64.zip
a3a1eca3081f9899ef4b0079732c698a7b2518c26c92519a93552d0137794821  sample-provider_0.0.0-SNAPSHOT-981ad9a_linux_amd64.zip
8586c8e3cd90d0d605cb5fdfb4abc916afffa0af446cdbf8744a59184d21ca93  sample-provider_0.0.0-SNAPSHOT-981ad9a_linux_arm64.zip
d6bee24374756c0ad1aca7beeeaa2fabecea94f1100c4572b0ca6b54eca0e204  sample-provider_0.0.0-SNAPSHOT-981ad9a_windows_amd64.zip
```

## How It Works

1. The endpoint parses the SHA256SUMS file to identify required provider files
2. Validates that all required `.zip` files are present in the upload
3. Verifies the SHA256 checksum of each file matches the SHA256SUMS
4. Extracts OS and architecture from filenames (format: `name_version_os_arch.zip`)
5. Stores all files in the OCI registry using the same structure as `cmd/generate.go`
6. Returns a success response with upload details

## Response

### Success (201 Created)
```json
{
  "status": "success",
  "message": "Provider uploaded successfully",
  "namespace": "hashicorp",
  "type": "sample-provider",
  "version": "0.0.0-SNAPSHOT-981ad9a",
  "tag": "v0.0.0-SNAPSHOT-981ad9a"
}
```

### Error Responses
- `400 Bad Request` - Missing required fields, files, or checksum mismatch
- `405 Method Not Allowed` - Non-POST request
- `500 Internal Server Error` - Server-side processing error

## Using the Upload Script

A convenience script is provided at `scripts/upload_provider.sh`:

```bash
# Basic usage
./scripts/upload_provider.sh <namespace> <type> <version> <dist-directory>

# Example with sample provider
./scripts/upload_provider.sh hashicorp sample-provider 0.0.0-SNAPSHOT-981ad9a pkg/registries/terraform/sample/dist

# With custom registry URL
REGISTRY_URL=http://localhost:8080 ./scripts/upload_provider.sh hashicorp sample-provider 1.0.0 ./dist
```

## Manual Upload with curl

```bash
curl -X POST http://localhost:8080/terraform/upload \
  -F "namespace=hashicorp" \
  -F "type=sample-provider" \
  -F "version=1.0.0" \
  -F "SHA256SUMS=@./dist/sample-provider_1.0.0_SHA256SUMS" \
  -F "SHA256SUMS.sig=@./dist/sample-provider_1.0.0_SHA256SUMS.sig" \
  -F "sample-provider_1.0.0_darwin_amd64.zip=@./dist/sample-provider_1.0.0_darwin_amd64.zip" \
  -F "sample-provider_1.0.0_darwin_arm64.zip=@./dist/sample-provider_1.0.0_darwin_arm64.zip" \
  -F "sample-provider_1.0.0_linux_amd64.zip=@./dist/sample-provider_1.0.0_linux_amd64.zip" \
  -F "sample-provider_1.0.0_linux_arm64.zip=@./dist/sample-provider_1.0.0_linux_arm64.zip" \
  -F "sample-provider_1.0.0_windows_amd64.zip=@./dist/sample-provider_1.0.0_windows_amd64.zip"
```

## Storage Format

The uploaded provider is stored in the OCI registry with the following structure:

- **Outer Index**: Contains the inner index as a manifest
- **Inner Index**: Contains all platform-specific manifests and annotations
  - SHA256SUMS stored as base64-encoded annotation
  - Signature (if provided) stored as base64-encoded annotation
- **Platform Manifests**: One per platform (OS/arch combination)
  - Contains the provider binary as a blob/layer
  - Platform metadata in the config
  - File name and digest in annotations
- **Tag**: `v{version}` (e.g., `v1.0.0`)

This format matches exactly what is produced by `cmd/generate.go`, ensuring compatibility with existing download endpoints.

## Authentication

If the OCI registry requires authentication, include credentials in the request headers or configure the registry client appropriately.


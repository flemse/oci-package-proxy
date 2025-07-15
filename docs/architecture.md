# Architecture

## Overview

This document provides an overview of the architecture for the OCI Package Proxy project.

## Components

- **cmd/**: Contains command-line tools for generating and managing registries.
- **pkg/**: Includes core packages for configuration, registries, and storage.
- **scripts/**: Contains utility scripts for installation and setup.
- **tmp/**: Temporary files and certificates.
- **appmgmt/**: OCI layout and blob storage.
- **pkg/package/config.go**: Handles package configuration loading and parsing.
- **pkg/registries/python/registry.go**: Implements Python PyPI registry interactions, including upload, download, and metadata handling.
- **pkg/registries/terraform/registry.go**: Implements Terraform provider registry interactions, including discovery, versioning, and downloads.
- **pkg/store/oci.go**: Manages OCI storage operations, including repository creation and artifact handling.

## Workflow

1. **Registry Management**:
   - Python PyPI registry supports upload, download, and metadata handling.
   - Terraform provider registry supports discovery, versioning, and downloads.
2. **Authentication**:
   - Validates user credentials for secure access.
3. **Storage**:
   - Uses OCI constructs for storing packages and metadata.

## Frontend Component

The application includes a frontend component designed to interface with various package types:
* Terraform provider (implemented)
* Terraform module 
* NuGet
* PyPI
* RubyGems

### Workflow

1. **Request Handling**: The frontend receives requests from package manager clients.
2. **Mapping**: A mapper construct translates package-specific requests into OCI-compatible calls.
3. **Registry Interaction**: The frontend forwards the mapped requests to the OCI registry.

### Mapper Construct

The mapper construct is a critical component that takes package identifiers and determines their corresponding location within the OCI registry. It performs lookups to translate package-specific identifiers (e.g., names, versions) into OCI-compatible paths or references. This ensures that requests from package manager clients are accurately routed to the correct storage location in the OCI registry.

### OCI Storage

To store packages in the OCI registry, the application uses OCI layouts. These layouts organize packages along with their metadata and support for different architectures. Each package is stored in a structured format that includes:

1. **Metadata**: Information about the package, such as name, version, and dependencies.
2. **Architectures**: Binary files or blobs for various supported architectures.
3. **Manifest**: A manifest file that describes the package contents and their relationships.

This approach ensures compatibility with OCI standards and provides a scalable way to manage packages across diverse ecosystems.
Packages are stored using OCI layouts, which include metadata, blobs, manifests, and indexes. The `pkg/store/oci.go` file defines constants and methods for handling Terraform provider artifacts and annotations.

## Future Enhancements

- Improved scalability.
- Enhanced security measures.
- Additional registry support.

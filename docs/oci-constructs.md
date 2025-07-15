# OCI Constructs

## Overview

OCI (Open Container Initiative) constructs are used in the OCI Package Proxy to store and manage packages as OCI artifacts.
These constructs provide a standardized way to organize, store, and retrieve packages, ensuring compatibility across different ecosystems.

## Key Components

### OCI Layouts

OCI layouts are used to structure the storage of packages in the OCI registry. Each layout includes:

1. **Metadata**: Information about the package, such as name, version, dependencies, and supported architectures.
2. **Blobs**: Binary files or other data associated with the package, stored in the `blobs/` directory.
3. **Manifest**: A manifest file that describes the package contents and their relationships.
4. **Index**: An `index.json` file that provides an entry point for the package layout.

### Updated OCI Layouts

The `pkg/store/oci.go` file defines constants and methods for handling Terraform provider artifacts and annotations, including:

1. **Artifact Type**: Specifies the type of artifact for Terraform providers.
2. **Annotations**: Includes keys for file digest, filename, shasum, and shasum signature.

### OCI Registry

The OCI registry serves as the storage backend for packages. It supports operations such as:

1. **Push**: Uploading packages and their metadata to the registry.
2. **Pull**: Downloading packages and their metadata from the registry.
3. **Search**: Querying the registry for specific packages.
4. **Authentication**: Validating user credentials and permissions for accessing the registry.

### Mapper Construct

The mapper construct is responsible for translating package-specific identifiers (e.g., names, versions) into OCI-compatible paths.
It ensures that requests from package manager clients are accurately routed to the correct storage location in the OCI registry.

## Workflow

1. **Package Preparation**:
   - Packages are prepared using OCI layouts, with metadata and blobs organized as per OCI standards.

2. **Registry Interaction**:
   - Managed using repository creation and artifact handling methods defined in `pkg/store/oci.go`.

3. **Request Handling**:
   - Requests from package manager clients are intercepted and mapped to OCI-compatible paths.

4. **Metadata Management**:
   - Metadata is stored and retrieved in a format compatible with the package manager protocols.

## Benefits

- **Standardization**: Ensures compatibility with OCI standards.
- **Scalability**: Supports large-scale storage and retrieval of packages.
- **Interoperability**: Enables integration with multiple package ecosystems.

## Future Enhancements

- Improved indexing and search capabilities.
- Enhanced security measures for package storage and retrieval.
- Support for additional package types and protocols.

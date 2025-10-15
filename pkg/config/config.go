package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type PackageType string

const (
	PackageTypeTerraform PackageType = "terraform"
	PackageTypePython    PackageType = "python"
)

type Package struct {
	Name        string        `json:"name" yaml:"name"`
	Type        PackageType   `json:"type" yaml:"type"`
	SigningKeys []*SigningKey `json:"signing_keys" yaml:"signingKeys"`
}

type SigningKeyList struct {
	GPGPublicKeys []*SigningKey `json:"gpg_public_keys"`
}

type SigningKey struct {
	KeyID      string `json:"key_id" yaml:"keyID"`
	ASCIIArmor string `json:"ascii_armor" yaml:"asciiArmor"`
}

type PackageList struct {
	Packages []Package `json:"packages" yaml:"packages"`
}

type HostConfig struct {
	Host          string
	OrgKey        string
	AllowInsecure bool
}

func LoadPackageConfig(path string) (*PackageList, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	var packageList PackageList
	if err := yaml.Unmarshal(data, &packageList); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &packageList, nil
}

// ServerConfig holds the configuration for the registry server
type ServerConfig struct {
	Port              string
	SkipTLS           bool
	CertFilePath      string
	KeyFilePath       string
	TLSCert           *tls.Certificate // Optional: use this instead of file paths
	HostOCI           string
	OrgName           string
	AllowInsecureOCI  bool
	PackageConfigFile string
	PackageList       *PackageList // Optional: use this instead of loading from file
}

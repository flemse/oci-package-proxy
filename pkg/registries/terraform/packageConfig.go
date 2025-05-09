package terraform

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Package struct {
	Name        string        `json:"name" yaml:"name"`
	SigningKeys []*SigningKey `json:"signing_keys" yaml:"signingKeys"`
}

type SigningKeyList struct {
	GPGPublicKeys []*SigningKey `json:"gpg_public_keys"`
}

type SigningKey struct {
	KeyID      string `json:"key_id" yaml:"keyID"`
	AsciiArmor string `json:"ascii_armor" yaml:"asciiArmor"`
}

type PackageList struct {
	Packages []Package `json:"packages" yaml:"packages"`
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

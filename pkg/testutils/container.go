package testutils

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	testImageBuilt     bool
	testImageBuildLock sync.Mutex
)

// EnsureTestImageBuilt builds the unified test image if it hasn't been built yet
func EnsureTestImageBuilt(ctx context.Context) error {
	testImageBuildLock.Lock()
	defer testImageBuildLock.Unlock()

	if testImageBuilt {
		return nil
	}

	// Get the project root directory (assuming we're in pkg/testutils)
	projectRoot, err := filepath.Abs("../../..")
	if err != nil {
		return fmt.Errorf("failed to get project root: %w", err)
	}

	// Build the test image using testcontainers
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			BuildOptionsModifier: func(options *types.ImageBuildOptions) {
				options.Tags = append(options.Tags, "oci-package-proxy-test:latest")
			},
			Context:        projectRoot,
			KeepImage:      true,
			Dockerfile:     "Dockerfile.test",
			BuildLogWriter: os.Stdout,
		},
	}

	// Build the image (GenericContainer with Started: false will just build)
	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          false,
	})
	if err != nil {
		return fmt.Errorf("failed to build test image: %w", err)
	}

	testImageBuilt = true
	return nil
}

func StartTestContainer(ctx context.Context) (string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/project-zot/zot:latest",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForLog("starting task"),
	}
	zotContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return "", fmt.Errorf("could not start zot container: %w", err)
	}
	h, err := zotContainer.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("could not get zot container host: %w", err)
	}
	p, err := zotContainer.MappedPort(ctx, "5000")
	if err != nil {
		return "", fmt.Errorf("could not get zot container port: %w", err)
	}

	return fmt.Sprintf("%s:%s", h, p.Port()), nil
}

func ReadExecOutput(reader io.Reader) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(reader)
	output := buf.Bytes()

	var result bytes.Buffer
	for len(output) > 0 {
		if len(output) < 8 {
			// If less than 8 bytes, just append what's left
			result.Write(output)
			break
		}
		// Read the payload size from bytes 4-7 (big-endian)
		payloadSize := int(output[4])<<24 | int(output[5])<<16 | int(output[6])<<8 | int(output[7])
		if payloadSize == 0 || len(output) < 8+payloadSize {
			// Invalid header or incomplete payload, return what we have
			result.Write(output[8:])
			break
		}
		// Extract payload
		result.Write(output[8 : 8+payloadSize])
		output = output[8+payloadSize:]
	}
	return strings.TrimSpace(result.String())
}

func StartPythonTestContainer(ctx context.Context) (testcontainers.Container, error) {
	if err := EnsureTestImageBuilt(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure test image is built: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:      "oci-package-proxy-test:latest",
		WaitingFor: wait.ForLog(""),
		Cmd:        []string{"sleep", "infinity"},
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func StartTerraformTestContainer(t *testing.T, ctx context.Context) (testcontainers.Container, error) {
	t.Helper()

	if err := EnsureTestImageBuilt(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure test image is built: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:      "oci-package-proxy-test:latest",
		WaitingFor: wait.ForLog(""),
		Cmd:        []string{"sleep", "infinity"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return container, nil
}

func StartGoReleaserContainer(t *testing.T, ctx context.Context) (testcontainers.Container, error) {
	t.Helper()

	if err := EnsureTestImageBuilt(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure test image is built: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:      "oci-package-proxy-test:latest",
		WaitingFor: wait.ForLog(""),
		Cmd:        []string{"sleep", "infinity"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return container, nil
}

// GenerateSelfSignedCert generates a self-signed certificate for testing
// Returns the certificate PEM, private key PEM, and tls.Certificate
func GenerateSelfSignedCert() (certPEM, keyPEM []byte, tlsCert tls.Certificate, err error) {
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "host.docker.internal"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEMBuffer := new(bytes.Buffer)
	if err := pem.Encode(certPEMBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("failed to encode certificate: %w", err)
	}
	certPEM = certPEMBuffer.Bytes()

	// Encode private key to PEM
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEMBuffer := new(bytes.Buffer)
	if err := pem.Encode(keyPEMBuffer, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("failed to encode private key: %w", err)
	}
	keyPEM = keyPEMBuffer.Bytes()

	// Create tls.Certificate
	tlsCert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("failed to create tls certificate: %w", err)
	}

	return certPEM, keyPEM, tlsCert, nil
}

// GenerateGPGKey generates a GPG key pair for testing and returns the public key in ASCII armor format and fingerprint
func GenerateGPGKey() (publicKeyArmor string, fingerprint string, privateKeyArmor string, err error) {
	// Create a new entity with all required settings
	name := "Test Key"
	email := "test-key@example.com"
	comment := ""

	entity, err := openpgp.NewEntity(name, comment, email, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create entity: %w", err)
	}

	// Export public key to ASCII armor
	pubBuf := new(bytes.Buffer)
	pubWriter, err := armor.Encode(pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create armor encoder: %w", err)
	}
	err = entity.Serialize(pubWriter)
	if err != nil {
		pubWriter.Close()
		return "", "", "", fmt.Errorf("failed to serialize public key: %w", err)
	}
	pubWriter.Close()
	publicKeyArmor = pubBuf.String()

	// Export private key to ASCII armor
	privBuf := new(bytes.Buffer)
	privWriter, err := armor.Encode(privBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create armor encoder for private key: %w", err)
	}
	err = entity.SerializePrivate(privWriter, nil)
	if err != nil {
		privWriter.Close()
		return "", "", "", fmt.Errorf("failed to serialize private key: %w", err)
	}
	privWriter.Close()
	privateKeyArmor = privBuf.String()

	// Get fingerprint (hex-encoded)
	fingerprint = fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)

	return publicKeyArmor, fingerprint, privateKeyArmor, nil
}

// ImportGPGKeyToContainer imports a GPG private key into a container
func ImportGPGKeyToContainer(ctx context.Context, container testcontainers.Container, privateKeyArmor, fingerprint string) error {
	// Copy the private key to the container
	err := container.CopyToContainer(ctx, []byte(privateKeyArmor), "/tmp/private-key.asc", 0600)
	if err != nil {
		return fmt.Errorf("failed to copy private key to container: %w", err)
	}

	// Import the key
	exitCode, output, err := container.Exec(ctx, []string{"gpg", "--batch", "--import", "/tmp/private-key.asc"})
	if err != nil {
		return fmt.Errorf("failed to execute GPG import: %w", err)
	}

	outputStr := ReadExecOutput(output)
	if exitCode != 0 {
		return fmt.Errorf("GPG import failed (exit %d): %s", exitCode, outputStr)
	}

	// Trust the key ultimately
	trustScript := fmt.Sprintf("echo '%s:6:' | gpg --import-ownertrust", fingerprint)
	exitCode, output, err = container.Exec(ctx, []string{"sh", "-c", trustScript})
	if err != nil {
		return fmt.Errorf("failed to execute GPG trust: %w", err)
	}

	outputStr = ReadExecOutput(output)
	if exitCode != 0 {
		return fmt.Errorf("GPG trust failed (exit %d): %s", exitCode, outputStr)
	}

	return nil
}

func TrustSSLCertInContainer(t *testing.T, ctx context.Context, container testcontainers.Container, certPEM []byte) {
	t.Helper()
	// Copy the certificate to the container
	err := container.CopyToContainer(ctx, certPEM, "/usr/local/share/ca-certificates/test-registry.crt", 0644)
	require.NoError(t, err, "Failed to copy certificate to container")

	// Update the CA certificates
	exitCode, output, err := container.Exec(ctx, []string{"update-ca-certificates"})
	require.NoError(t, err)
	outputStr := ReadExecOutput(output)
	t.Logf("update-ca-certificates output: %s", outputStr)
	require.Equal(t, 0, exitCode, "update-ca-certificates failed")
}

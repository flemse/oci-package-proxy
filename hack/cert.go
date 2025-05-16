package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	if _, err := os.ReadFile("tmp/cert.pem"); !os.IsNotExist(err) {
		log.Println("cert.pem already exists, skipping generation.")
		return
	}
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LEGO Test org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "localhost.test"},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(nil, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Write the certificate to cert.pem
	certFile, err := os.Create("tmp/cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		log.Fatalf("Failed to write certificate: %v", err)
	}

	// Write the private key to key.pem
	keyFile, err := os.Create("tmp/key.pem")
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	defer keyFile.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write private key: %v", err)
	}

	log.Println("Self-signed certificate and private key generated: cert.pem, key.pem")

	log.Print(`To trust the certificate, add it to your system's trusted root CA store.
On MacOS, you can do this by running:
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain tmp/cert.pem`)
}

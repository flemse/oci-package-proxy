package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/flemse/oci-package-proxy/pkg/registries/terraform/auth"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
)

type CredsFetcher struct {
	EncryptionKey []byte
}

func GenerateFingerprint(r *http.Request) string {
	h := sha256.New()

	//remove port
	ipAddress := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(ipAddress); err == nil {
		ipAddress = ip
	}
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ipParts := strings.Split(forwardedFor, ",")
		ipAddress = strings.TrimSpace(ipParts[0])
	}
	h.Write([]byte(ipAddress))

	h.Write([]byte(r.UserAgent()))

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		h.Write(r.TLS.PeerCertificates[0].Raw)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (f *CredsFetcher) FromRequest(r *http.Request) *orasauth.Credential {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		return f.fromAuthHeader(authHeader)
	}

	token := r.URL.Query().Get("token")
	if token != "" && f.EncryptionKey != nil {
		return f.fromToken(token, r)
	}

	return nil
}

func (f *CredsFetcher) fromAuthHeader(authHeader string) *orasauth.Credential {
	if strings.HasPrefix(authHeader, "Basic ") {
		decoded, err := decodeBasicAuth(authHeader)
		if err == nil {
			return &orasauth.Credential{
				Username: decoded[0],
				Password: decoded[1],
			}
		}
	}
	if strings.HasPrefix(authHeader, "Bearer ") {
		return &orasauth.Credential{
			Username: "oauth2",
			Password: strings.TrimPrefix(authHeader, "Bearer "),
		}
	}

	return nil
}

func (f *CredsFetcher) fromToken(encryptedToken string, request *http.Request) *orasauth.Credential {
	token, err := auth.Decrypt(f.EncryptionKey, encryptedToken, GenerateFingerprint(request))
	if err != nil {
		log.Printf("Error decrypting token: %v", err)
		return nil
	}
	return &orasauth.Credential{
		Username: "oauth2",
		Password: token,
	}
}

func decodeBasicAuth(header string) ([]string, error) {
	encoded := strings.TrimPrefix(header, "Basic ")
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(string(decodedBytes), ":", 2)
	if len(parts) != 2 {
		return nil, err
	}
	return parts, nil
}

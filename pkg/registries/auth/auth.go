package auth

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrExpiredToken        = errors.New("token expired")
	ErrFingerprintMismatch = errors.New("fingerprint mismatch")
	timeSince              = time.Since // For testing purposes
)

type Envelope struct {
	Auth               string    `json:"t"`
	Timestamp          time.Time `json:"ts"`
	RequestFingerprint string    `json:"rfp"`
	TTL                int       `json:"ttl"`
}

// Encrypt the authentication envelope using AES-GCM
func Encrypt(key []byte, auth, fingerprint string) (string, error) {
	// Create an envelope containing the auth and current timestamp
	envelope := Envelope{
		Auth:               auth,
		Timestamp:          time.Now(),
		RequestFingerprint: fingerprint,
		TTL:                300, // 5 minutes validity
	}

	// Encode the envelope to JSON
	data, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}

	data, err = compress(data)
	if err != nil {
		return "", fmt.Errorf("failed to compress: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := aesgcm.Seal(nonce, nonce, data, nil)

	// Base64 encode for URL safety
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt and validates the authentication token
func Decrypt(key []byte, encryptedBlob, fingerprint string) (string, error) {
	// Decode base64
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedBlob)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create a new GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	if len(ciphertext) < aesgcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:aesgcm.NonceSize()], ciphertext[aesgcm.NonceSize():]

	// Decrypt
	data, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	data, err = decompress(data)
	if err != nil {
		return "", fmt.Errorf("failed to decompress: %w", err)
	}

	// Unmarshal envelope
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", err
	}

	// Validate timestamp
	if timeSince(envelope.Timestamp).Seconds() > float64(envelope.TTL) {
		return "", ErrExpiredToken
	}

	// Validate fingerprint
	if envelope.RequestFingerprint != fingerprint {
		return "", ErrFingerprintMismatch
	}

	return envelope.Auth, nil
}

func compress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return nil, errors.New("compression failed")
	}
	if err := w.Close(); err != nil {
		return nil, errors.New("compression failed")
	}
	return b.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("decompression failed")
	}
	defer r.Close()

	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		return nil, errors.New("decompression failed")
	}
	return b.Bytes(), nil
}

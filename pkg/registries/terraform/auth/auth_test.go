package auth

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var timeSinceFiveMinutesInFuture = func(t time.Time) time.Duration {
	return time.Now().Add(5 * time.Minute).Sub(t)
}

func TestEncrypt_Success(t *testing.T) {
	key := generateKey()

	auth := "test_auth"
	fingerprint := "test_fingerprint"
	encrypted, err := Encrypt(key, auth, fingerprint)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Check if the encrypted string is base64 encoded
	_, err = base64.URLEncoding.DecodeString(encrypted)
	assert.NoError(t, err)
}

func TestDecrypt_Success(t *testing.T) {
	key := generateKey()

	auth := "test_authsomething something something something"
	fingerprint := "test_fingerprint"
	encrypted, err := Encrypt(key, auth, fingerprint)
	assert.NoError(t, err)
	decrypted, err := Decrypt(key, encrypted, fingerprint)
	assert.NoError(t, err)
	assert.Equal(t, auth, decrypted)
}

func TestDecrypt_Failure(t *testing.T) {
	key := generateKey()

	invalidToken := "invalid_token"
	_, err := Decrypt(key, invalidToken, "")
	assert.Error(t, err)
}

func TestDecrypt_key_mismatch_Failure(t *testing.T) {
	key := generateKey()

	auth := "test_auth"
	fingerprint := "test_fingerprint"
	encrypted, err := Encrypt(key, auth, fingerprint)
	assert.NoError(t, err)
	decrypted, err := Decrypt(make([]byte, 32), encrypted, fingerprint)
	assert.Error(t, err)
	assert.Empty(t, decrypted)
}

func TestDecrypt_fingerprint_mismatch_Failure(t *testing.T) {
	key := generateKey()

	auth := "test_auth"
	fingerprint := "test_fingerprint"
	encrypted, err := Encrypt(key, auth, fingerprint)
	assert.NoError(t, err)
	decrypted, err := Decrypt(key, encrypted, "invalid_fingerprint")
	assert.ErrorIs(t, err, ErrFingerprintMismatch)
	assert.Empty(t, decrypted)
}

func TestDecrypt_expired_token_Failure(t *testing.T) {
	key := generateKey()

	t.Cleanup(func() {
		timeSince = time.Since
	})
	timeSince = timeSinceFiveMinutesInFuture

	auth := "test_auth"
	fingerprint := "test_fingerprint"
	encrypted, err := Encrypt(key, auth, fingerprint)
	assert.NoError(t, err)
	decrypted, err := Decrypt(key, encrypted, fingerprint)
	assert.ErrorIs(t, err, ErrExpiredToken)
	assert.Empty(t, decrypted)
}

func generateKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic("failed to generate random key")
	}

	return key
}

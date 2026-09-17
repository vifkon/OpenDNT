package main

import (
	"crypto/rand"

	"github.com/flynn/noise"
)

// newCipherSuite задаёт тройку примитивов протокола: X25519 для DH,
// ChaCha20-Poly1305 для AEAD, BLAKE2b для хэширования/KDF внутри Noise
func newCipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
}

// generateStaticKeypair генерирует эфемерный статический keypair узла.
// Пока не записывается на диск - при каждом запуске узел получает новую
// идентичность, это известный и пока не закрытый пробел
func generateStaticKeypair(cs noise.CipherSuite) (noise.DHKey, error) {
	return cs.GenerateKeypair(rand.Reader)
}

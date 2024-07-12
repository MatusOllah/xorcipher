// Package xorcipher implements XOR Cipher.
package xorcipher

import (
	"crypto/cipher"
	"strconv"
)

// The XOR Cipher "block size" in bytes.
const BlockSize = 1

// KeySizeError represents an error due to an invalid key size.
type KeySizeError int

// Error returns a string representation of the KeySizeError k.
func (k KeySizeError) Error() string {
	return "xorcipher: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new [cipher.Block]. It returns an error if the key length is zero.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) == 0 {
		return nil, KeySizeError(len(key))
	}

	return &xorCipher{key}, nil
}

var _ cipher.Block = (*xorCipher)(nil)

// xorCipher implements the [cipher.Block] interface for XOR cipher.
type xorCipher struct {
	key []byte
}

// BlockSize returns the block size.
func (c *xorCipher) BlockSize() int {
	return BlockSize
}

// Encrypt encrypts src and writes ciphertext to dst. It panics if the destination buffer is too small.
func (c *xorCipher) Encrypt(dst, src []byte) {
	if len(dst) < len(src) {
		panic("destination buffer is too small")
	}
	xorEncryptDecrypt(c.key, dst, src)
}

// Decrypt decrypts src and writes plaintext to dst. It panics if the destination buffer is too small.
func (c *xorCipher) Decrypt(dst, src []byte) {
	if len(dst) < len(src) {
		panic("destination buffer is too small")
	}
	xorEncryptDecrypt(c.key, dst, src)
}

// xorEncryptDecrypt performs the XOR operation for encryption and decryption.
func xorEncryptDecrypt(key, dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ key[i%len(key)]
	}
}

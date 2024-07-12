package xorcipher_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/MatusOllah/xorcipher"
)

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestNewCipherValidKey(t *testing.T) {
	// test case: valid key
	block, err := xorcipher.NewCipher([]byte("horalky"))
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	bs := block.BlockSize()
	if bs != xorcipher.BlockSize {
		t.Errorf("expected block size %d, got %d", xorcipher.BlockSize, bs)
	}

}

func TestNewCipherInvalidKey(t *testing.T) {
	// test case: invalid / empty key
	_, err := xorcipher.NewCipher([]byte{})
	if err == nil {
		t.Errorf("expected err for invalid key, got nil")
	}
	if _, ok := err.(xorcipher.KeySizeError); !ok {
		t.Errorf("expected KeySizeError, got %T", err)
	}
	expectedErrMsg := "xorcipher: invalid key size 0"
	if err.Error() != expectedErrMsg {
		t.Errorf("expected error message %s, got %s", expectedErrMsg, err.Error())
	}

}

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name               string
		key                []byte
		plaintext          []byte
		expectedCiphertext []byte
	}{
		{"ShortPlaintextMediumKey", []byte("horalky"), []byte("Hello, World!"), decodeHex("200a1e0d0347593f00000d084a")},
		{"ShortPlaintextLongKey", []byte("horalkysedita"), []byte("Hello, World!"), decodeHex("200a1e0d034759240a16051040")},
		{"ShortPlaintextShortKey", []byte("bf"), []byte("Hello, World!"), decodeHex("2a030e0a0d4a42310d140e0243")},
		{"ShortPlaintextSingleCharKey", []byte("a"), []byte("Hello, World!"), decodeHex("29040d0d0e4d41360e130d0540")},
		{"LongPlaintextMediumKey", []byte("horalky"), []byte("Longer Plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), decodeHex("24001c0609195938031308021f1c101b52202d2a38292e33202d2a38292e33202d2a38292e33202d2a38292e33202d2a38292e")},
		{"LongPlaintextLongKey", []byte("horalkysedita"), []byte("Longer Plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), decodeHex("24001c06091959230905001a150d1706412d2a38322425283520292e33202d2a38322425283520292e33202d2a383224252835")},
		{"LongPlaintextShortKey", []byte("bf"), []byte("Longer Plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), decodeHex("2e090c01071442360e070b0816031a124227232723272327232723272327232723272327232723272327232723272327232723")},
		{"LongPlaintextSingleCharKey", []byte("a"), []byte("Longer Plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), decodeHex("2d0e0f06041341310d00080f150419154120202020202020202020202020202020202020202020202020202020202020202020")},
		{"SingleCharPlaintextMediumKey", []byte("horalky"), []byte("a"), decodeHex("09")},
		{"SingleCharPlaintextLongKey", []byte("horalkysedita"), []byte("a"), decodeHex("09")},
		{"SingleCharPlaintextShortKey", []byte("bf"), []byte("a"), decodeHex("03")},
		{"SingleCharPlaintextSingleCharKey", []byte("a"), []byte("A"), decodeHex("20")},
		{"EmptyPlaintext", []byte("horalky"), []byte(""), decodeHex("")},
		{"KeyEqualToPlaintextLengthMediumKey", []byte("horalky"), []byte("horalky"), decodeHex("00000000000000")},
		{"KeyEqualToPlaintextLengthLongKey", []byte("horalkysedita"), []byte("horalkysedita"), decodeHex("00000000000000000000000000")},
		{"KeyEqualToPlaintextLengthShortKey", []byte("bf"), []byte("bf"), decodeHex("0000")},
		{"KeyEqualToPlaintextLengthSingleCharKey", []byte("a"), []byte("a"), decodeHex("00")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block, err := xorcipher.NewCipher(test.key)
			if err != nil {
				t.Fatal(err)
			}

			ciphertext := make([]byte, len(test.expectedCiphertext))
			decryptedText := make([]byte, len(test.plaintext))

			block.Encrypt(ciphertext, test.plaintext)
			if !bytes.Equal(test.expectedCiphertext, ciphertext) {
				t.Errorf("expected ciphertext %x, got %x", test.expectedCiphertext, ciphertext)
			}

			block.Decrypt(decryptedText, ciphertext)
			if !bytes.Equal(test.plaintext, decryptedText) {
				t.Errorf("expected plaintext %s, got %s", test.plaintext, decryptedText)
			}
		})
	}
}

func TestEncryptWithDifferentBufferSizes(t *testing.T) {
	key := []byte("horalky")
	block, err := xorcipher.NewCipher(key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	plaintext := []byte("Test buffer sizes")
	ciphertext := make([]byte, len(plaintext)+1) // larger buffer

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for insufficient buffer size, but did not get one")
		} else {
			// Check for the specific panic message
			if msg, ok := r.(string); ok && msg != "destination buffer is too small" {
				t.Errorf("expected specific panic message, got %v", msg)
			}
		}
	}()

	// This should cause a panic due to insufficient buffer size
	block.Encrypt(ciphertext[:len(plaintext)-1], plaintext)
}

func TestDecryptWithDifferentBufferSizes(t *testing.T) {
	key := []byte("horalky")
	block, err := xorcipher.NewCipher(key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ciphertext := decodeHex("3c0a01154c090c0e0917134c1810120a01")
	plaintext := make([]byte, len(ciphertext)-1)

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for insufficient buffer size, but did not get one")
		} else {
			// Check for the specific panic message
			if msg, ok := r.(string); ok && msg != "destination buffer is too small" {
				t.Errorf("expected specific panic message, got %v", msg)
			}
		}
	}()

	// This should cause a panic due to insufficient buffer size
	block.Decrypt(plaintext[:len(plaintext)-1], ciphertext)
}

func BenchmarkEncrypt(b *testing.B) {
	block, err := xorcipher.NewCipher([]byte("horalky"))
	if err != nil {
		b.Fatal(err)
	}
	plaintext := []byte("Benchmarking XOR Cipher encryption")
	ciphertext := make([]byte, len(plaintext))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		block.Encrypt(ciphertext, plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	block, err := xorcipher.NewCipher([]byte("horalky"))
	if err != nil {
		b.Fatal(err)
	}
	ciphertext := decodeHex("2a0a1c020406181a041b0f0b4b21273d5222051b110d1d520509080b111f06080305")
	plaintext := make([]byte, len(ciphertext))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		block.Decrypt(plaintext, ciphertext)
	}
}

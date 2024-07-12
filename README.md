# xorcipher

**xorcipher** is a XOR Cipher library for Go.

## Basic Usage

```go
package main

import (
    "fmt"
    "encoding/hex"

    "github.com/MatusOllah/xorcipher"
)

func main() {
    key := []byte("horalky")
    plaintext := []byte("Hello, World!")

    block, err := xorcipher.NewCipher(key)
    if err != nil {
        panic(err)
    }

    ciphertext := make([]byte, len(plaintext))
    block.Encrypt(ciphertext, plaintext)

    fmt.Println(hex.EncodeToString(ciphertext)) // > 200a1e0d0347593f00000d084a
}
```

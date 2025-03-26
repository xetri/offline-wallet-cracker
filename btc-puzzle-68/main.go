package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

const (
    StartHex = "80000000000000000"
    EndHex   = "fffffffffffffffff"
    TARGET_COMP_ADDR = "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"
)

var (
    numThreads = runtime.NumCPU()
    DIFF = big.NewInt(3966)
    targetPKhash = addressToPublicKeyHash(TARGET_COMP_ADDR)
)

func main() {
    fmt.Println("Searching:>")

    min := new(big.Int)
    min.SetString(StartHex, 16)
    max := new(big.Int)
    max.SetString(EndHex, 16)
    rangeDiff := new(big.Int).Add(new(big.Int).Sub(max, min), big.NewInt(1))

    for {
        var wg sync.WaitGroup
        for range numThreads {
            wg.Add(1)
            go func() {
                defer wg.Done()

                random, _ := rand.Int(rand.Reader, rangeDiff)
                random = new(big.Int).Add(min, random)
                scan(random)
            }()
        }
        wg.Wait()
    }
}

func addressToPublicKeyHash(addr string) string {
    hash := base58.Decode(addr)
    pkhash := hash[1:len(hash)-4]
    return hex.EncodeToString(pkhash)
}

func privateKeyToPublicKeyHash(privKey *big.Int) string {
	ecdsaPrivKey, _ := btcec.PrivKeyFromBytes(privKey.Bytes())
	pubKey := ecdsaPrivKey.PubKey().SerializeCompressed()

	// SHA-256 hash
	sha := sha256.Sum256(pubKey)
	// RIPEMD-160 hash
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	pubKeyHash := ripemd.Sum(nil)

    return hex.EncodeToString(pubKeyHash)
}

func scan(basenum *big.Int) {
	current := new(big.Int).Sub(basenum, DIFF)
    final := new(big.Int).Add(basenum, DIFF)
	one := big.NewInt(1)

	for current.Cmp(final) <= 0 {
		pkhash := privateKeyToPublicKeyHash(current)

		if pkhash == targetPKhash {
            fmt.Printf("FOUND ^&^: %s\n", current.Text(16))
            saveToFile(current.Text(16))
            os.Exit(0)
		}

		current.Add(current, one)
	}
}

func saveToFile(key string) {
    f, err := os.OpenFile("./found_key.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
         fmt.Println("Error opening file:", err)
         return
    }

    defer f.Close() // Ensure file is closed after function returns
    _, err = f.WriteString(key + "\n") // Append key with a newline

    if err != nil {
         fmt.Println("Error appending to file:", err)
    } else {

         fmt.Println("Private key appended to found_key.txt")
    }
}

func RandInt(min, max *big.Int) *big.Int {
    diff := new(big.Int).Sub(max, min)
    diff.Add(diff, big.NewInt(1))

    random, _ := rand.Int(rand.Reader, diff)

    return new(big.Int).Add(random, min)
}

// Generate Bitcoin address from private key
// func generateAddress(privKey *big.Int) string {
// 	// Convert private key to ECDSA format
// 	ecdsaPrivKey, _ := btcec.PrivKeyFromBytes(privKey.Bytes())
// 
// 	// Get public key (compressed)
// 	pubKey := ecdsaPrivKey.PubKey().SerializeCompressed()
// 
// 	// SHA-256 hash
// 	sha := sha256.Sum256(pubKey)
// 
// 	// RIPEMD-160 hash
// 	ripemd := ripemd160.New()
// 	ripemd.Write(sha[:])
// 	pubKeyHash := ripemd.Sum(nil)
// 
// 	// Add Bitcoin version byte (0x00 for mainnet)
// 	versionedHash := append([]byte{0x00}, pubKeyHash...)
// 
// 	// Double SHA-256 for checksum
// 	checksum := sha256.Sum256(versionedHash)
// 	checksum = sha256.Sum256(checksum[:])
// 
// 	// Append first 4 bytes of checksum
// 	finalHash := append(versionedHash, checksum[:4]...)
// 
// 	// Convert to Base58 address
// 	address := base58.Encode(finalHash)
// 
// 	return address
// }

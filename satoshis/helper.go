package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"math/big"
    "os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	"github.com/btcsuite/btcutil/bech32"
)

func privKeyToWIF(privKey *big.Int, compressed bool) string {
    privKeyBytes := privKey.Bytes()

	// Ensure it's exactly 32 bytes (pad with leading zeros if necessary)
	if len(privKeyBytes) < 32 {
		padding := make([]byte, 32-len(privKeyBytes))
		privKeyBytes = append(padding, privKeyBytes...)
	}

	// Prefix with 0x80 for Bitcoin mainnet
	wifBytes := append([]byte{0x80}, privKeyBytes...)

	// If using a compressed key, append 0x01
	if compressed {
		wifBytes = append(wifBytes, 0x01)
	}

	// Double SHA-256 to generate checksum
	hash1 := sha256.Sum256(wifBytes)
	hash2 := sha256.Sum256(hash1[:])

	// Append first 4 bytes of the checksum
	wifBytes = append(wifBytes, hash2[:4]...)

	// Convert to Base58
	wif := base58.Encode(wifBytes)
	return wif
}

func generateP2SHAddress(privKey *btcec.PrivateKey) string {
	// Step 1: Get the compressed public key
	pubKey := privKey.PubKey().SerializeCompressed()

	// Step 2: Create a P2WPKH redeem script (0x00 <20-byte pubKeyHash>)
	sha := sha256.Sum256(pubKey)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	pubKeyHash := ripemd.Sum(nil)

	// Standard P2WPKH nested in P2SH redeem script (OP_0 <PubKeyHash>)
	redeemScript := append([]byte{0x00, 0x14}, pubKeyHash...) // OP_0 (0x00) + Push 20 bytes (0x14) + PubKeyHash

	// Step 3: Hash the redeem script (SHA-256 → RIPEMD-160)
	shaRedeem := sha256.Sum256(redeemScript)
	ripemd.Reset()
	ripemd.Write(shaRedeem[:])
	scriptHash := ripemd.Sum(nil)

	// Step 4: Add the version byte (0x05 for P2SH mainnet)
	versionedHash := append([]byte{0x05}, scriptHash...)

	// Step 5: Compute the checksum (Double SHA-256)
	hash1 := sha256.Sum256(versionedHash)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]

	// Step 6: Append checksum and encode in Base58Check
	finalHash := append(versionedHash, checksum...)
	address := base58.Encode(finalHash)

	return address
}

// Generate Bitcoin address from private key
func generateP2PKHAddress(privKey *big.Int) (string) {
	ePrivKey, _ := btcec.PrivKeyFromBytes(privKey.Bytes())

	// Get public key (compressed)
    pubKey := ePrivKey.PubKey().SerializeCompressed()

	// SHA-256 hash
	sha := sha256.Sum256(pubKey)
	// RIPEMD-160 hash
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	pubKeyHash := ripemd.Sum(nil)
	// Add Bitcoin version byte (0x00 for mainnet)
	versionedHash := append([]byte{0x00}, pubKeyHash...)
	// Double SHA-256 for checksum
	checksum := sha256.Sum256(versionedHash)
	checksum = sha256.Sum256(checksum[:])
	// Append first 4 bytes of checksum
	finalHash := append(versionedHash, checksum[:4]...)
	// Convert to Base58 address
	address := base58.Encode(finalHash)
	return address
}

func generateSegWitAddress(privKey *big.Int) (string) {
	ePrivKey, _ := btcec.PrivKeyFromBytes(privKey.Bytes())
	// Step 1: Get the compressed public key
	pubKey := ePrivKey.PubKey().SerializeCompressed()

	// Step 2: Perform SHA-256 hash to get the public key hash (P2WPKH)
	sha := sha256.Sum256(pubKey)
	pubKeyHash := sha[:]

	// Step 3: Convert to Bech32 format (SegWit version 0, witness program = pubKeyHash)
	converted, err := bech32.ConvertBits(pubKeyHash, 8, 5, true)
	if err != nil {
		return ""
	}

	// Step 4: Encode in Bech32 with human-readable part (HRP = "bc" for mainnet)
	address, err := bech32.Encode("bc", append([]byte{0x00}, converted...))
	if err != nil {
		return ""
	}

	return address
}

func saveToFile(fpath, data string) {
    f, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Println("Error opening file:", err)
        return
    }
    defer f.Close() // Ensure file is closed after function returns

    _, err = f.WriteString(data + "\n") // Append key with a newline
    if err != nil {
        fmt.Println("Error appending to file:", err)
    } else {
        fmt.Println("Private key appended to found_key.txt")
    }
}

// Load funded Bitcoin addresses into a hash set for fast lookup
func loadFundedAddresses(filename string) map[string]struct{} {
    file, err := os.Open(filename)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    funded := make(map[string]struct{})
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        funded[scanner.Text()] = struct{}{}
    }

    return funded
}

func exist(address string, targets *map[string]struct{}) bool {
    _, exists := (*targets)[address]
    return exists
}

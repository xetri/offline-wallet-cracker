package main

import (
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/bech32"
	"golang.org/x/crypto/ripemd160"
)

// converts private key to WIF Key
func PrivateKeyToWIF(privateKey *big.Int, compressed bool) string {
    privateKeyBytes := privateKey.Bytes()

	// Ensure it's exactly 32 bytes (pad with leading zeros if necessary)
	if len(privateKeyBytes) < 32 {
		padding := make([]byte, 32 - len(privateKeyBytes))
		privateKeyBytes = append(padding, privateKeyBytes...)
	}

	// Prefix with 0x80 for Bitcoin mainnet
	wifBytes := append([]byte{0x80}, privateKeyBytes...)

	// If using a compressed key, append 0x01
	if compressed {
		wifBytes = append(wifBytes, 0x01)
	}

	// Double SHA-256 to generate checksum
    checksum := sha256Hash(sha256Hash(wifBytes))[:4]

	// Append the checksum
    wifBytes = append(wifBytes, checksum...)

	// Convert to Base58
	wif := base58.Encode(wifBytes)

	return wif
}

// converts WIF key to private key
func WIFKeyToPrivateKey(wif string) *big.Int {
    // Decode the WIF key
    wifBytes := base58.Decode(wif)

    // Remove the version byte (0x80) and the checksum
    privateKeyBytes := wifBytes[1 : len(wifBytes)-4]

    // If the last byte is 0x01, it's a compressed key
    compressed := len(privateKeyBytes) > 32

    if compressed {
        privateKeyBytes = privateKeyBytes[:len(privateKeyBytes)-1]
    }

    privateKey := new(big.Int).SetBytes(privateKeyBytes)

    return privateKey
}

// generates public key bytes from private key
func PublicKey(privateKey *big.Int, compressed bool) []byte {
    privateKeyBytes := privateKey.Bytes()

    if len(privateKeyBytes) < 32 {
        padding := make([]byte, 32 - len(privateKeyBytes))
        privateKeyBytes = append(padding, privateKeyBytes...)
	}

    ePrivKey, _ := btcec.PrivKeyFromBytes(privateKey.Bytes())

    if compressed {  
        return ePrivKey.PubKey().SerializeCompressed() 
    }
    return ePrivKey.PubKey().SerializeUncompressed()
}

// generates P2PKH address from public key bytes
func P2PKH_Address(publicKey []byte) string {
    publicKeyHash := ripemd160Hash(sha256Hash(publicKey))

    versionedHash := append([]byte{0x00}, publicKeyHash...)
    checksum := sha256Hash(sha256Hash(versionedHash))[:4]

    finalHash := append(versionedHash, checksum...)

    return base58.Encode(finalHash)
}

// generates P2WPKH address from public key bytes [Bech32]
func P2WPKH_Address(publicKey []byte) string {
    publicKeyHash := ripemd160Hash(sha256Hash(publicKey))

    convertedBytes, _ := bech32.ConvertBits(publicKeyHash, 8, 5, true)
	witnessBytes := append([]byte{0x00}, convertedBytes...) 
    address, _ := bech32.Encode("bc", witnessBytes)

    return address
}

// generates P2SH (P2SH => P2WPKH) address from public key bytes [Nested Segwit] (Default: P2SH)
func P2SH_P2WPKH_Address(publicKey []byte) string {
    publicKeyHash := ripemd160Hash(sha256Hash(publicKey))

    // OP_0 (0x00) + Push 20 bytes (0x14) + PubKeyHash
	script := append([]byte{0x00, 0x14}, publicKeyHash...) 
    scriptHash := ripemd160Hash(sha256Hash(script))

    // 0x05 for P2SH mainnet
    versionedHash := append([]byte{0x05}, scriptHash...)
    checksum := sha256Hash(sha256Hash(versionedHash))[:4]

    finalHash := append(versionedHash, checksum...)

    return base58.Encode(finalHash)
}

// generates P2SH (P2SH => P2PKH) address from public key bytes 
func P2SH_P2PKH_Address(publicKey []byte) string {
    publicKeyHash := ripemd160Hash(sha256Hash(publicKey))

    // OP_DUP (0x76) + OP_HASH160 (0xA9) + Push 20 bytes (0x14) + PubKeyHash + OP_EQUALVERIFY (0x88) + OP_CHECKSIG (0xAC)
    script := []byte{0x76, 0xA9, 0x14}
    script = append(script, publicKeyHash...)
    script = append(script, 0x88, 0xAC)

    scriptHash := ripemd160Hash(sha256Hash(script))

    // 0x05 for P2SH mainnet
    versionedHash := append([]byte{0x05}, scriptHash...)
    checksum := sha256Hash(sha256Hash(versionedHash))[:4]

    finalHash := append(versionedHash, checksum...)

    return base58.Encode(finalHash)
}

// generates P2WSH (P2WSH => P2WPKH) address from public key bytes (Default: P2WSH) [Bech32]
func P2WSH_P2WPKH_Address(publicKey []byte) string {
    publicKeyHash := ripemd160Hash(sha256Hash(publicKey))

    // OP_0 (0x00) + Push 20 bytes (0x14) + PubKeyHash
	script := append([]byte{0x00, 0x14}, publicKeyHash...) 

    // SHA-256 hash of the redeem script
    scriptHash := sha256Hash(script)

    // Convert 8-bit hash to 5-bit chunks
    convertedBytes, _ := bech32.ConvertBits(scriptHash, 8, 5, true)
    
    // Prepend witness version (0x00 for P2WSH)
    witnessBytes := append([]byte{0x00}, convertedBytes...)
    
    // Bech32 encoding for native SegWit
    address, _ := bech32.Encode("bc", witnessBytes)
    
    return address
}

// generates P2WSH (P2WSH => P2PKH) address from public key bytes [Bech32]
func P2WSH_P2PKH_Address(publicKey []byte) string {
    publicKeyHash := ripemd160Hash(sha256Hash(publicKey))

    // Generate the P2PKH script
    script := []byte{0x76, 0xA9, 0x14}
    script = append(script, publicKeyHash...)
    script = append(script, 0x88, 0xAC)

    // Calculate the SHA-256 hash of the P2PKH script
    scriptHash := sha256Hash(script)

    // Convert 8-bit hash to 5-bit chunks
    convertedBytes, _ := bech32.ConvertBits(scriptHash, 8, 5, true)

    // Prepend witness version (0x00 for P2WSH)
    witnessBytes := append([]byte{0x00}, convertedBytes...)

    // Bech32 encoding for native SegWit
    address, _ := bech32.Encode("bc", witnessBytes)

    return address}

func sha256Hash(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

func ripemd160Hash(data []byte) []byte {
    ripemd := ripemd160.New()
    ripemd.Write(data)
    return ripemd.Sum(nil)
}

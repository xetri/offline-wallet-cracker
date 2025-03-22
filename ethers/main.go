package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
    "runtime"

	"github.com/ethereum/go-ethereum/crypto"
)

// Load funded Ethereum addresses into a hash map
func loadFundedAddresses(filename string) map[string]struct{} {
    file, err := os.Open(filename)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    funded := make(map[string]struct{})
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        address := strings.TrimSpace(scanner.Text())
        funded[address] = struct{}{}
    }
    return funded
}

func generateEthereumAddressPvkey(pvkey *big.Int) (string, string) {
    privateKey := new(ecdsa.PrivateKey)
    privateKey.PublicKey.Curve = crypto.S256()
    privateKey.D = pvkey
    privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())

    privKeyBytes := crypto.FromECDSA(privateKey)
    address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

    return strings.ToLower(hex.EncodeToString(privKeyBytes)), strings.ToLower(address[2:])
}

// Generate a random Ethereum private key and address
func generateEthereumAddress() (string, string) {
    privKey, err := crypto.GenerateKey()
    if err != nil {
        panic(err)
    }
    privKeyBytes := crypto.FromECDSA(privKey)
    address := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
    return hex.EncodeToString(privKeyBytes), address
}

func scanRange(start, end *big.Int, targets *map[string]struct{}) {
	current := new(big.Int).Set(start)
	one := big.NewInt(1)

	for current.Cmp(end) <= 0 {
		pvkey, address := generateEthereumAddressPvkey(current)
        if _, exists := (*targets)[address]; exists {
			fmt.Printf("Found! ETH Private Key: %s | Address: %s", pvkey, address)
            saveToFile(pvkey, address)
            // os.Exit(0)
		}

        fmt.Printf("%s {::} %s\n", pvkey, address)

		current.Add(current, one)
	}
}

func saveToFile(pvkey string, addr string) {
    file, err := os.Create("found_eth_keys.txt")
    if err != nil {
        panic(err)
    }
    defer file.Close()

    writer := bufio.NewWriter(file)
    writer.WriteString(fmt.Sprintf("PrivateKey: %s | Address: %s\n", pvkey, addr))
    writer.Flush()
}

func main() {
    fundedAddresses := loadFundedAddresses("ethers.hex")
    DIFF := big.NewInt(12345)
    
    fmt.Println("Successfully mapped funded ETH addressses")
    fmt.Println("Scanning:>")

    numThreads := runtime.NumCPU()

    var wg sync.WaitGroup
    for range numThreads {
        wg.Add(1)

        go func() {
            defer wg.Done()
            for {
                privKeyBytes := make([]byte, 32)
                rand.Read(privKeyBytes)
                privKey := new(big.Int).SetBytes(privKeyBytes)

                start := new(big.Int).Sub(privKey, DIFF)
                end := new(big.Int).Add(privKey, DIFF)

                scanRange(start, end, &fundedAddresses)
            }
        } ()

    }
    wg.Wait()

}

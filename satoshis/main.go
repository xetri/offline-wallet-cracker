package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"sync"
    "os"
)

var (
    numThreads = runtime.NumCPU()
)

func main() {
    addresses := loadFundedAddresses("./satoshis.hex")
    DIFF := big.NewInt(512)

    fmt.Println("Scanning:>")

	var wg sync.WaitGroup
	for _ = range numThreads {
	    wg.Add(1)
        go func() {
            defer wg.Done()
            for {
                privKeyBytes := make([]byte, 32)
                _, err := rand.Read(privKeyBytes)
                if err != nil {
                    panic(err)
                }

                privKey := new(big.Int).SetBytes(privKeyBytes)

                scanRange(new(big.Int).Sub(privKey, DIFF), new(big.Int).Add(privKey, DIFF), &addresses)
            }
        }()
    }
    wg.Wait()
}

func scanRange(start, end *big.Int, targets *map[string]struct{}) {
	current := new(big.Int).Set(start)
	one := big.NewInt(1)

	for current.Cmp(end) <= 0 {
        key, addr := privKeyToWIF(current, true), generateP2PKHAddress(current)
        if _, exists := (*targets)[addr]; exists {
			fmt.Sprintf("Found! Private Key: %s || Address: %s", key, addr)
            saveToFile("founds.txt", key)
            os.Exit(0)
		}

        fmt.Printf("Addr: %s {::} Key: %s\n", addr, key)

		current.Add(current, one)
	}
}

// I have become crypto, the destroyer of fiat.
// I have become blockchain, the destroyer of privacy.
// I have become deadlock, the blocker of threads.
// I am become segfault, the crasher of programs.
// I am become panic, the handler of last resort.

package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"
)

var (
	numThreads = runtime.NumCPU()
	DIFF       = big.NewInt(12345)
)

func main() {
	// Load funded addresses
	fmt.Println("Loading funded addresses...")
	p2pkhAddresses := loadFundedAddresses("P2PKH.txt")
	p2shAddresses := loadFundedAddresses("P2SH.txt")
	p2wpkhAddresses := loadFundedAddresses("P2WPKH.txt")
	p2wshAddresses := loadFundedAddresses("P2WSH.txt")

	fmt.Println("Scanning: P2PKH, P2SH, P2WPKH, P2WSH")
	var wg sync.WaitGroup
	for range numThreads {
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
				one := big.NewInt(1)

				start := new(big.Int).Sub(privKey, DIFF)
				end := new(big.Int).Add(privKey, DIFF)

				current := new(big.Int).Set(start)

				for current.Cmp(end) <= 0 {
					key := current.Text(16)
					publicKeyCompressed := PublicKey(current, true)
					publicKeyUncompressed := PublicKey(current, false)

					p2pkh_comp := P2PKH_Address(publicKeyCompressed)
					p2pkh_uncomp := P2PKH_Address(publicKeyUncompressed)

					p2sh_p2wpkh_comp := P2SH_P2WPKH_Address(publicKeyCompressed)
					p2sh_p2wpkh_uncomp := P2SH_P2WPKH_Address(publicKeyUncompressed)

					p2sh_p2pkh_comp := P2SH_P2PKH_Address(publicKeyCompressed)
					p2sh_p2pkh_uncomp := P2SH_P2PKH_Address(publicKeyUncompressed)

					p2wpkh_comp := P2WPKH_Address(publicKeyCompressed)
					p2wpkh_uncomp := P2WPKH_Address(publicKeyUncompressed)

					p2wsh_p2wpkh_comp := P2WSH_P2WPKH_Address(publicKeyCompressed)
					p2wsh_p2wpkh_uncomp := P2WSH_P2WPKH_Address(publicKeyUncompressed)

					p2wsh_p2pkh_comp := P2WSH_P2PKH_Address(publicKeyCompressed)
					p2wsh_p2pkh_uncomp := P2WSH_P2PKH_Address(publicKeyUncompressed)

					// Check if any of the addresses are funded
					ref := fmt.Sprintf("Found! Private Key: %s", key)
					fmt.Printf("PrivateKey: %v\n", key)

					//Begins with 1
					_, exists_comp := p2pkhAddresses[p2pkh_comp]
					_, exists_uncomp := p2pkhAddresses[p2pkh_uncomp]
					if exists_comp || exists_uncomp {
						fmt.Printf("Comp: %v, Uncomp: %v\n", p2pkh_comp, p2pkh_uncomp)
						fmt.Println(ref)
						saveToFile("satoshis-founds.txt", ref)
					}

					//Begins with 3
					_, exists_comp = p2shAddresses[p2sh_p2wpkh_comp]
					_, exists_uncomp = p2shAddresses[p2sh_p2wpkh_uncomp]
					if exists_comp || exists_uncomp {
						fmt.Printf("Comp: %v, Uncomp: %v\n", p2sh_p2wpkh_comp, p2sh_p2wpkh_uncomp)
						fmt.Println(ref)
						saveToFile("satoshis-founds.txt", ref)
					}

					_, exists_comp = p2shAddresses[p2sh_p2pkh_comp]
					_, exists_uncomp = p2shAddresses[p2sh_p2pkh_uncomp]
					if exists_comp || exists_uncomp {
						fmt.Printf("Comp: %v, Uncomp: %v\n", p2sh_p2pkh_comp, p2sh_p2pkh_uncomp)
						fmt.Println(ref)
						saveToFile("satoshis-founds.txt", ref)
					}

					//Begins with bc1 (42)
					_, exists_comp = p2wpkhAddresses[p2wpkh_comp]
					_, exists_uncomp = p2wpkhAddresses[p2wpkh_uncomp]
					if exists_comp || exists_uncomp {
						fmt.Printf("Comp: %v, Uncomp: %v\n", p2wpkh_comp, p2wpkh_uncomp)
						fmt.Println(ref)
						saveToFile("satoshis-founds.txt", ref)
					}

					//Begins with bc1 (62)
					_, exists_comp = p2wshAddresses[p2wsh_p2wpkh_comp]
					_, exists_uncomp = p2wshAddresses[p2wsh_p2wpkh_uncomp]
					if exists_comp || exists_uncomp {
						fmt.Printf("Comp: %v, Uncomp: %v\n", p2wsh_p2wpkh_comp, p2wsh_p2wpkh_uncomp)
						fmt.Println(ref)
						saveToFile("satoshis-founds.txt", ref)
					}

					_, exists_comp = p2wshAddresses[p2wsh_p2pkh_comp]
					_, exists_uncomp = p2wshAddresses[p2wsh_p2pkh_uncomp]
					if exists_comp || exists_uncomp {
						fmt.Printf("Comp: %v, Uncomp: %v\n", p2wsh_p2pkh_comp, p2wsh_p2pkh_uncomp)
						fmt.Println(ref)
						saveToFile("satoshis-founds.txt", ref)
					}

					current.Add(current, one)
				}
			}
		}()
	}
	wg.Wait()
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

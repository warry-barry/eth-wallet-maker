package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	log := logrus.New()

	// Generate a mnemonic
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Fatalf("Failed to generate entropy: %v", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatalf("Failed to create mnemonic: %v", err)
	}

	// Derive a key from the mnemonic
	path := accounts.DefaultBaseDerivationPath
	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := crypto.ToECDSA(seed[:32])
	if err != nil {
		log.Fatalf("Failed to create master key: %v", err)
	}

	// Extract the private key
	privateKey := hex.EncodeToString(crypto.FromECDSA(masterKey))

	// Save the mnemonic, derivation path, private key, and address to a file
	file, err := os.Create("eth-key-details.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("Mnemonic: %s\n", mnemonic))
	if err != nil {
		log.Errorf("Failed to write mnemonic to file: %v", err)
	}

	_, err = file.WriteString(fmt.Sprintf("Derivation Path: %s\n", path.String()))
	if err != nil {
		log.Errorf("Failed to write derivation path to file: %v", err)
	}

	_, err = file.WriteString(fmt.Sprintf("Private Key: %s\n", privateKey))
	if err != nil {
		log.Errorf("Failed to write private key to file: %v", err)
	}

	address := crypto.PubkeyToAddress(masterKey.PublicKey)
	_, err = file.WriteString(fmt.Sprintf("Address: %s\n", address.Hex()))
	if err != nil {
		log.Errorf("Failed to write address to file: %v", err)
	}

	log.Info("Ethereum key details written to eth-key-details.txt")
}

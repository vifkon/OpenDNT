package main

import (
	"fmt"
	"log"
	"net"

	"github.com/flynn/noise"
)

func main() {
	fmt.Println("OpenDNT node starting...")

	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	staticKeyPair, err := cs.GenerateKeypair(nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Node public key: %x\n", staticKeyPair.Public)

	_ = listener
}

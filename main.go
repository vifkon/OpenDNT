package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	mode := flag.String("mode", "listen", "listen or dial")
	flag.Parse()
	if *mode != "listen" && *mode != "dial" {
		fmt.Println("Неправильный режим. Юзай 'listen' или 'dial'.")
		return
	}

	cs := newCipherSuite()
	staticKeypair, err := generateStaticKeypair(cs)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("OpenDNT узел запущен, режим:", *mode)

	if *mode == "listen" {
		err = runServer(cs, staticKeypair)
	} else {
		err = runClient(cs, staticKeypair)
	}

	if err != nil {
		log.Fatal(err)
	}
}

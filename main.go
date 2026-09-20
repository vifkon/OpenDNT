package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	mode := flag.String("mode", "listen", "listen, dial или relay")
	keyPath := flag.String("key", "node.key", "путь к файлу с приватным ключом")
	flag.Parse()

	// режим проверяем ДО загрузки ключа: опечатка не должна создавать файл ключа
	switch *mode {
	case "listen", "dial", "relay":
	default:
		fmt.Println("Неправильный режим. Юзай 'listen', 'dial' или 'relay'.")
		return
	}

	cs := newCipherSuite()
	staticKeypair, err := loadOrCreateKeypair(cs, *keyPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("OpenDNT узел запущен, режим:", *mode)
	fmt.Printf("Публичный ключ: %x\n", staticKeypair.Public)

	in := newStdin()
	switch *mode {
	case "listen":
		err = runServer(cs, staticKeypair, in)
	case "dial":
		err = runClient(cs, staticKeypair, in)
	case "relay":
		err = runRelay(cs, staticKeypair)
	}

	if err != nil {
		log.Fatal(err)
	}
}

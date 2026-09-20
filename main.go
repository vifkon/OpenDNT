package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	mode := flag.String("mode", "listen", "listen, dial или relay")
	keyPath := flag.String("key", "node.key", "путь к файлу с приватным ключом")
	relayAddr := flag.String("relayaddr", "", "только для dial: ip:порт релея, через который идти к конечному узлу")
	addr := flag.String("addr", "", "ip:порт: для listen/relay адрес прослушивания (по умолчанию :9000), для dial адрес назначения")
	flag.Parse()

	// режим проверяем ДО загрузки ключа: опечатка не должна создавать файл ключа
	switch *mode {
	case "listen", "dial", "relay":
	default:
		fmt.Println("Неправильный режим. Юзай 'listen', 'dial' или 'relay'.")
		return
	}

	if *relayAddr != "" && *mode != "dial" {
		fmt.Println("-relayaddr работает только с -mode dial")
		return
	}

	if *addr == "" {
		if *mode == "dial" {
			fmt.Println("Для режима dial нужен -addr ip:порт")
			return
		}
		*addr = ":9000"
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
		err = runServer(cs, staticKeypair, in, *addr)
	case "dial":
		if *relayAddr != "" {
			err = runClientViaRelay(cs, staticKeypair, in, *relayAddr, *addr)
		} else {
			err = runClient(cs, staticKeypair, in, *addr)
		}
	case "relay":
		err = runRelay(cs, staticKeypair, *addr)
	}

	if err != nil {
		log.Fatal(err)
	}
}

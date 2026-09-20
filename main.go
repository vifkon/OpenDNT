package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
)

func main() {
	mode := flag.String("mode", "listen", "listen, dial или relay")
	keyPath := flag.String("key", "node.key", "путь к файлу с приватным ключом")
	relayAddr := flag.String("relayaddr", "", "только для dial: ip:порт релея, через который идти к конечному узлу")
	addr := flag.String("addr", "", "ip:порт: для listen/relay адрес прослушивания (по умолчанию :9000), для dial адрес назначения")
	targetKeyHex := flag.String("targetkey", "", "только для dial: публичный ключ цели (hex, строка 'Публичный ключ' у неё в логе); если ключ в хендшейке другой - рвём соединение")
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

	if *targetKeyHex != "" && *mode != "dial" {
		fmt.Println("-targetkey работает только с -mode dial")
		return
	}
	var targetKey []byte
	if *targetKeyHex != "" {
		k, decErr := hex.DecodeString(strings.TrimSpace(*targetKeyHex))
		if decErr != nil || len(k) != keySize {
			fmt.Println("-targetkey должен быть 64 hex-символа (32 байта), как в строке 'Публичный ключ' у цели")
			return
		}
		targetKey = k
	}
	if *mode == "dial" && targetKey == nil {
		fmt.Println("Внимание: -targetkey не задан, ключ цели не проверяется (через релей цель можно подменить)")
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
			err = runClientViaRelay(cs, staticKeypair, in, *relayAddr, *addr, targetKey)
		} else {
			err = runClient(cs, staticKeypair, in, *addr, targetKey)
		}
	case "relay":
		err = runRelay(cs, staticKeypair, *addr)
	}

	if err != nil {
		log.Fatal(err)
	}
}

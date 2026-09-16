package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/flynn/noise"
)

func runListener(cs noise.CipherSuite, staticKeypair noise.DHKey) error {
	config := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: staticKeypair,
		Initiator:     false,
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Слушаец на :9000, ждём соединения...")

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("Подключение принято от:", conn.RemoteAddr())

	buf := make([]byte, 65535)

	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		return err
	}
	fmt.Println("Получено handshake-сообщение 1 (-> e), байт:", n)

	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg)
	if err != nil {
		return err
	}
	fmt.Println("Отправлено handshake-сообщение 2 (<- e, ee, s, es), байт:", len(msg))

	n, err = conn.Read(buf)
	if err != nil {
		return err
	}
	// Слушающий узел получает cs1/cs2 на третьем шаге так же, как и dialer -
	// но роли у него зеркальные: cs1 тут "чужое -> моё" (расшифровка),
	// cs2 - "моё -> чужое" (шифрование). У узла который отправляет было наоборот.
	_, cs1, cs2, err := hs.ReadMessage(nil, buf[:n])
	if err != nil {
		return err
	}
	fmt.Println("Получено handshake-сообщение 3 (-> s, se), байт:", n)
	fmt.Println("Handshake завершён, с:", conn.RemoteAddr())

	go func() {
		readBuf := make([]byte, 65535)
		for {
			n, err := conn.Read(readBuf)
			if err != nil {
				fmt.Println("\nСоединение закрыто:", err)
				return
			}
			plaintext, err := cs1.Decrypt(nil, nil, readBuf[:n])
			if err != nil {
				fmt.Println("\nОшибка расшифровки:", err)
				return
			}
			fmt.Println("\nСобеседник:", string(plaintext))
			fmt.Print("Введите сообщение: ")
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Введите сообщение: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		text = strings.TrimRight(text, "\r\n")

		ciphertext, err := cs2.Encrypt(nil, nil, []byte(text))
		if err != nil {
			return err
		}
		_, err = conn.Write(ciphertext)
		if err != nil {
			return err
		}
	}
}

func runDialer(cs noise.CipherSuite, staticKeypair noise.DHKey) error {
	config := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: staticKeypair,
		Initiator:     true,
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return err
	}

	var ipishnik string
	fmt.Print("Введите айпи: ")
	fmt.Scan(&ipishnik)

	addr := fmt.Sprintf("%s:9000", ipishnik)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("Подключился к", addr)

	buf := make([]byte, 65535)

	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg)
	if err != nil {
		return err
	}
	fmt.Println("Отправлено handshake-сообщение 1 (-> e), байт:", len(msg))

	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		return err
	}
	fmt.Println("Получено handshake-сообщение 2 (<- e, ee, s, es), байт:", n)

	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg2)
	if err != nil {
		return err
	}
	fmt.Println("Отправлено handshake-сообщение 3 (-> s, se), байт:", len(msg2))
	fmt.Println("Handshake завершён")

	go func() {
		readBuf := make([]byte, 65535)
		for {
			n, err := conn.Read(readBuf)
			if err != nil {
				fmt.Println("\nСоединение закрыто:", err)
				return
			}
			plaintext, err := cs2.Decrypt(nil, nil, readBuf[:n])
			if err != nil {
				fmt.Println("\nОшибка расшифровки:", err)
				return
			}
			fmt.Println("\nСобеседник:", string(plaintext))
			fmt.Print("Введите сообщение: ")
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Введите сообщение: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		text = strings.TrimRight(text, "\r\n")

		ciphertext, err := cs1.Encrypt(nil, nil, []byte(text))
		if err != nil {
			return err
		}
		_, err = conn.Write(ciphertext)
		if err != nil {
			return err
		}
	}
}

func main() {
	mode := flag.String("mode", "listen", "listen or dial")
	flag.Parse()
	if *mode != "listen" && *mode != "dial" {
		fmt.Println("Неправильный режим. Юзай 'listen' или 'dial'.")
		return
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	staticKeypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("OpenDNT узел запущен, режим:", *mode)

	if *mode == "listen" {
		err = runListener(cs, staticKeypair)
	} else {
		err = runDialer(cs, staticKeypair)
	}

	if err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/flynn/noise"
)

// runChat гоняет двунаправленный зашифрованный чат поверх conn, используя
// уже согласованные после хендшейка ключи. send шифрует то, что мы пишем,
// recv расшифровывает то, что приходит от собеседника. Роль (кто был
// listener, кто dialer) здесь уже не имеет значения
func runChat(conn net.Conn, send, recv *noise.CipherState) error {
	go func() {
		for {
			ciphertext, err := readFrame(conn)
			if err != nil {
				fmt.Println("\nСоединение закрыто:", err)
				return
			}
			plaintext, err := recv.Decrypt(nil, nil, ciphertext)
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

		ciphertext, err := send.Encrypt(nil, nil, []byte(text))
		if err != nil {
			return err
		}
		if err := writeFrame(conn, ciphertext); err != nil {
			return err
		}
	}
}

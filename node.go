package main

import (
	"fmt"
	"time"

	"github.com/flynn/noise"
)

// runServer поднимает TLS listener на :9000 и крутится в цикле accept,
// пока не найдёт реального пира: любое подключение, которое не проходит
// Noise-хендшейк (браузер, сканер порта, кто угодно, кто не говорит на
// нашем протоколе), просто отбрасывается - процесс продолжает жить и
// слушать дальше, а не падает через log.Fatal в main

// позже будет многопирный режим, но пока что это просто один пир, который может быть
func runServer(cs noise.CipherSuite, staticKeypair noise.DHKey) error {
	ln, err := listenUTLS(":9000")
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Слушаем на :9000, ждём соединения...")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Ошибка accept:", err)
			continue
		}
		fmt.Println("Подключение принято от:", conn.RemoteAddr())

		// таймаут будет ток на этап хендшейка: если за 5 секунд собеседник не провёл Noise_XX (то есть это не наш узел),
		// отваливаемся и идём слушать дальше, а не висим вечно из-за этого ненужного соединения
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		recv, send, err := handshakeServer(conn, cs, staticKeypair)
		if err != nil {
			fmt.Println("Хендшейк не прошёл (не наш протокол?):", err)
			conn.Close()
			continue
		}

		conn.SetDeadline(time.Time{}) // ну кароч если хендшейк наш, снимаем таймаут для чата
		defer conn.Close()

		return runChat(conn, send, recv)
	}
}

// проводит соединение через handshake + chat
func runClient(cs noise.CipherSuite, staticKeypair noise.DHKey) error {
	var ip string
	fmt.Print("Введите айпи: ")
	fmt.Scan(&ip)

	addr := fmt.Sprintf("%s:9000", ip)
	conn, err := dialUTLS(addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("Подключился к", addr)

	recv, send, err := handshakeClient(conn, cs, staticKeypair)
	if err != nil {
		return err
	}

	return runChat(conn, send, recv)
}

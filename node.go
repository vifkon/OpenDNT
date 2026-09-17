package main

import (
	"fmt"
	"net"

	"github.com/flynn/noise"
)

// runServer поднимает TCP listener на :9000, принимает ровно одно
// соединение и проводит его через handshake + chat

// Известный пробел (уже отмечен в overview): нет accept-цикла на
// несколько пиров, обрабатывается только одно соединение за запуск
func runServer(cs noise.CipherSuite, staticKeypair noise.DHKey) error {
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

	recv, send, err := handshakeServer(conn, cs, staticKeypair)
	if err != nil {
		return err
	}

	return runChat(conn, send, recv)
}

// проводит соединение через handshake + chat
func runClient(cs noise.CipherSuite, staticKeypair noise.DHKey) error {
	var ip string
	fmt.Print("Введите айпи: ")
	fmt.Scan(&ip)

	addr := fmt.Sprintf("%s:9000", ip)
	conn, err := net.Dial("tcp", addr)
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

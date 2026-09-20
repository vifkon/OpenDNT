package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/flynn/noise"
)

func runRelay(cs noise.CipherSuite, kp noise.DHKey, addr string) error {
	ln, err := listenUTLS(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Релей слушает на", addr)

	acceptLoop(ln, cs, kp, func(p peer) { handleRelayPeer(p, cs, kp) })
	return nil
}

func handleRelayPeer(p peer, cs noise.CipherSuite, kp noise.DHKey) {
	defer p.conn.Close()

	typ, payload, err := recvCmd(p)
	if err != nil {
		fmt.Println("Релей: ошибка чтения команды:", err)
		return
	}
	if typ != cmdConnect {
		fmt.Println("Релей: ожидали CONNECT, пришло:", typ)
		return
	}
	target := string(payload)
	fmt.Println("Релей: просят подключиться к", target)

	out, err := dialUTLS(target)
	if err != nil {
		sendCmd(p, cmdErr, []byte(err.Error()))
		return
	}
	defer out.Close()

	out.SetDeadline(time.Now().Add(handshakeTimeout))
	recv, send, err := handshakeClient(out, cs, kp)
	if err != nil {
		sendCmd(p, cmdErr, []byte(err.Error()))
		return
	}
	out.SetDeadline(time.Time{})
	next := peer{conn: out, send: send, recv: recv}

	if err := sendCmd(p, cmdOK, nil); err != nil {
		return
	}
	fmt.Println("Релей: соединение с", target, "установлено")

	errc := make(chan error, 2)
	go func() { errc <- forwardToTarget(p, next) }()
	go func() { errc <- forwardToClient(next, p) }()

	err = <-errc
	fmt.Println("Релей: закрываем", target, "-", err)
	// defer закроет оба соединения, и по иттогу вторая горутина завершится с ошибкой чтения
}

// forwardToTarget: команда DATA от клиента -> перешифровать -> цели
func forwardToTarget(from, to peer) error {
	for {
		typ, payload, err := recvCmd(from)
		if err != nil {
			return err
		}
		if typ != cmdData {
			return fmt.Errorf("неожиданная команда %d", typ)
		}
		ct, err := to.send.Encrypt(nil, nil, payload)
		if err != nil {
			return err
		}
		if err := writeFrame(to.conn, ct); err != nil {
			return err
		}
		fmt.Printf("Релей: %s -> %s, %d байт\n", from.conn.RemoteAddr(), to.conn.RemoteAddr(), len(payload))
	}
}

// forwardToClient: фрейм от цели -> расшифровать -> завернуть в DATA -> клиенту
func forwardToClient(from, to peer) error {
	for {
		ct, err := readFrame(from.conn)
		if err != nil {
			return err
		}
		pt, err := from.recv.Decrypt(nil, nil, ct)
		if err != nil {
			return err
		}
		if err := sendCmd(to, cmdData, pt); err != nil {
			return err
		}
		fmt.Printf("Релей: %s -> %s, %d байт\n", from.conn.RemoteAddr(), to.conn.RemoteAddr(), len(pt))
	}
}

// runClientViaRelay - режим dial с -relayaddr: идём к target через релей
func runClientViaRelay(cs noise.CipherSuite, kp noise.DHKey, in *bufio.Reader, relayAddr, target string) error {
	conn, err := dialUTLS(relayAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("Подключился к релею", relayAddr)

	recv, send, err := handshakeClient(conn, cs, kp)
	if err != nil {
		return err
	}
	p := peer{conn: conn, send: send, recv: recv}

	if err := sendCmd(p, cmdConnect, []byte(target)); err != nil {
		return err
	}
	typ, payload, err := recvCmd(p)
	if err != nil {
		return err
	}
	switch typ {
	case cmdOK:
		fmt.Println("Релей подключился к", target)
	case cmdErr:
		return fmt.Errorf("релей не смог подключиться: %s", payload)
	default:
		return fmt.Errorf("неожиданный ответ релея: %d", typ)
	}

	return chatViaRelay(p, in)
}

// chatViaRelay - тот же чат, что runChat, но поверх команд DATA
func chatViaRelay(p peer, in *bufio.Reader) error {
	netDone := make(chan error, 1)
	go func() {
		for {
			typ, payload, err := recvCmd(p)
			if err != nil {
				netDone <- err
				return
			}
			if typ == cmdData {
				fmt.Println("\nСобеседник:", string(payload))
				fmt.Print("Введите сообщение: ")
			}
		}
	}()

	lines := make(chan string)
	inErr := make(chan error, 1)
	go func() {
		for {
			text, err := in.ReadString('\n')
			if err != nil {
				inErr <- err
				return
			}
			lines <- strings.TrimRight(text, "\r\n")
		}
	}()

	for {
		fmt.Print("Введите сообщение: ")
		select {
		case text := <-lines:
			// +1 байт на тип команды; проверяем до Encrypt
			if len(text)+1 > maxPlaintext {
				fmt.Println("Слишком длинное сообщение")
				continue
			}
			if err := sendCmd(p, cmdData, []byte(text)); err != nil {
				return err
			}
		case err := <-netDone:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case err := <-inErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

package main

import (
	"bufio"
	"fmt"
	"net"

	"github.com/flynn/noise"
)

// runRelay - слушаем и принимаем клиентов. cs и kp нужны только для хендшейка
// клиент<->релей, его делает acceptLoop. С целью релей Noise больше не
// говорит вообще - см. handleRelayPeer
func runRelay(cs noise.CipherSuite, kp noise.DHKey, addr string) error {
	ln, err := listenUTLS(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Релей слушает на", addr)

	acceptLoop(ln, cs, kp, handleRelayPeer)
	return nil
}

// handleRelayPeer: ждём CONNECT, открываем только TLS до цели и дальше просто
// гоним байты туда-сюда. Раньше релей сам делал Noise с целью и
// перешифровывал всё - то есть видел весь плейнтекст, чего мы и не хотели.
// Теперь Noise клиент<->цель едет внутри DATA как обычные байты, и
// расшифровать их релей не может - у него нет тех ключей
func handleRelayPeer(p peer) {
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

	if err := sendCmd(p, cmdOK, nil); err != nil {
		return
	}
	fmt.Println("Релей: соединение с", target, "установлено")

	errc := make(chan error, 2)
	go func() { errc <- pipeToTarget(p, out) }()
	go func() { errc <- pipeToClient(out, p) }()

	err = <-errc
	fmt.Println("Релей: закрываем", target, "-", err)
	// deferы закроют оба соединения, и вторая горутина по итогу вылетит с ошибкой чтения
}

// pipeToTarget: DATA от клиента -> достаём байты -> в цель как есть
// вкратце это чужой Noise, внутри фреймы
// со своим префиксом длины, релею туда лезть незачем
func pipeToTarget(from peer, to net.Conn) error {
	for {
		typ, payload, err := recvCmd(from)
		if err != nil {
			return err
		}
		if typ != cmdData {
			return fmt.Errorf("неожиданная команда %d", typ)
		}
		if _, err := to.Write(payload); err != nil {
			return err
		}
		// первые байты в hex - чисто чтобы глазами убедиться, что там каша, а не текст
		fmt.Printf("Релей: клиент -> цель, %d байт, начало: %x\n", len(payload), payload[:min(len(payload), 16)])
	}
}

// pipeToClient: что прочитали из цели -> заворачиваем в DATA -> клиенту.
// Читаем поток кусками, не фреймами: где кончается сообщение, знает только
// клиент, релей этого не видит и не должен
func pipeToClient(from net.Conn, to peer) error {
	buf := make([]byte, maxChunk)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			if err := sendCmd(to, cmdData, buf[:n]); err != nil {
				return err
			}
			fmt.Printf("Релей: цель -> клиент, %d байт, начало: %x\n", n, buf[:min(n, 16)])
		}
		if err != nil {
			return err
		}
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

	// хендшейк №1: клиент <-> релей, это линк
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

	// хендшейк №2: клиент <-> цель, СКВОЗЬ релей. Дальше все ключи с
	// префиксом e2e - это ключи цели, релей их не знает
	rc := newRelayConn(p)
	e2eRecv, e2eSend, err := handshakeClient(rc, cs, kp)
	if err != nil {
		return err
	}
	return runChat(rc, e2eSend, e2eRecv, in)
}

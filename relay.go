package main

import (
	"fmt"

	"github.com/flynn/noise"
)

// runRelay - листенер без чата: принимает много пиров одновременно.
// serveConn уже крутится в своей горутине на каждое соединение, поэтому
// блокирующий handleRelayPeer не мешает приёму остальных
func runRelay(cs noise.CipherSuite, kp noise.DHKey) error {
	ln, err := listenUTLS(":9000")
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Релей слушает на :9000")

	acceptLoop(ln, cs, kp, handleRelayPeer) // блокируется, пока не закроют listener
	return nil
}

// handleRelayPeer - заглушка - просто читаем фреймы и не делаем нихера с ними. Попозже пересылка появится
func handleRelayPeer(p peer) {
	defer p.conn.Close()
	for {
		ct, err := readFrame(p.conn)
		if err != nil {
			fmt.Println("Пир ушёл:", p.conn.RemoteAddr(), err)
			return
		}
		pt, err := p.recv.Decrypt(nil, nil, ct)
		if err != nil {
			fmt.Println("Ошибка расшифровки от", p.conn.RemoteAddr(), err)
			return
		}
		fmt.Printf("Релей: %d байт от %s\n", len(pt), p.conn.RemoteAddr())
	}
}

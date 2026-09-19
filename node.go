package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"
)

// handshakeTimeout - сколько даём собеседнику на TLS + Noise_XX. Кто не
// уложился - не наш узел (или сканер, который держит сокет открытым)
const handshakeTimeout = 5 * time.Second

// peer - соединение, уже прошедшее хендшейк, вместе с ключами
type peer struct {
	conn       net.Conn
	send, recv *noise.CipherState
}

// runServer поднимает TLS listener на :9000. Accept-цикл крутится в
// отдельной горутине, а каждое входящее соединение проходит хендшейк в
// СВОЕЙ горутине: медленный или молчащий клиент (сканер) не может
// заблокировать приём остальных. Первый, кто реально прошёл Noise_XX,
// попадает в канал ready, и с ним запускается чат

// позже будет многопирный режим, но пока что это просто один пир
func runServer(cs noise.CipherSuite, staticKeypair noise.DHKey, in *bufio.Reader) error {
	ln, err := listenUTLS(":9000")
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Слушаем на :9000, ждём соединения...")

	// буфер 1: победитель кладёт пира, не дожидаясь, пока main дойдёт
	// до чтения из канала
	ready := make(chan peer, 1)
	go acceptLoop(ln, cs, staticKeypair, ready)

	p := <-ready
	defer p.conn.Close()
	return runChat(p.conn, p.send, p.recv, in)
}

// acceptLoop принимает соединения, пока listener не закроют
func acceptLoop(ln net.Listener, cs noise.CipherSuite, kp noise.DHKey, ready chan<- peer) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener закрыт (runServer вернулся) - выходим
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Println("Ошибка accept:", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		fmt.Println("Подключение принято от:", conn.RemoteAddr())
		go serveConn(conn, cs, kp, ready)
	}
}

// serveConn прогоняет одно входящее соединение через хендшейк. Всё, что
// не говорит на нашем протоколе (браузер, сканер порта), просто отбрасывается
func serveConn(conn net.Conn, cs noise.CipherSuite, kp noise.DHKey, ready chan<- peer) {
	// дедлайн только на этап хендшейка. TLS-хендшейк у crypto/tls ленивый
	// и случается внутри первого чтения, так что дедлайн покрывает и его
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	recv, send, err := handshakeServer(conn, cs, kp)
	if err != nil {
		fmt.Println("Хендшейк не прошёл (не наш протокол?):", err)
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // хендшейк наш - для чата дедлайн снимаем

	select {
	case ready <- peer{conn: conn, send: send, recv: recv}:
	default:
		// пир уже есть (одновременно прошли хендшейк двое) - лишнего закрываем
		fmt.Println("Пир уже подключён, отбрасываем:", conn.RemoteAddr())
		conn.Close()
	}
}

// проводит соединение через handshake + chat
func runClient(cs noise.CipherSuite, staticKeypair noise.DHKey, in *bufio.Reader) error {
	fmt.Print("Введите айпи: ")
	// читаем строку целиком тем же readerом, что потом уйдёт в чат: так
	// перевод строки после IP не остаётся в stdin и не превращается в
	// пустое первое сообщение (fmt.Scan забирал только слово)
	line, err := in.ReadString('\n')
	if err != nil {
		return err
	}
	ip := strings.TrimSpace(line)
	if ip == "" {
		return errors.New("пустой айпи")
	}

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

	return runChat(conn, send, recv, in)
}

// newStdin - единственный буферизованный reader на stdin
func newStdin() *bufio.Reader { return bufio.NewReader(os.Stdin) }

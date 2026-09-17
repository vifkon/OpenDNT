package main

import (
	"encoding/binary"
	"io"
)

// writeFrame пишет сообщение с 2-байтовым префиксом длины (big-endian)
// Максимальный размер сообщения - 65535 байт, этого хватает и для
// handshake-сообщений Noise, и для отдельных чат-реплик
func writeFrame(w io.Writer, msg []byte) error {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(msg)))
	if _, err := w.Write(length[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// readFrame читает ровно один фрейм: сначала длину, потом тело
func readFrame(r io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(length[:])
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

package main

import (
	"context"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// RawConn holds the File's fd reference/read lock only for the short syscall.
// Returning true even for EAGAIN/EINTR forbids RawRead from waiting for a packet.
func h2ReadyRead(raw syscall.RawConn, packet []byte) (int, bool, error) {
	return h2ReadyReadUsing(raw, packet, unix.Read)
}

func h2ReadyReadUsing(raw syscall.RawConn, packet []byte, read func(int, []byte) (int, error)) (int, bool, error) {
	var length int
	var readErr error
	err := raw.Read(func(fd uintptr) bool {
		length, readErr = read(int(fd), packet)
		return true
	})
	if err != nil {
		return 0, false, err
	}
	if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EWOULDBLOCK) || errors.Is(readErr, unix.EINTR) {
		return 0, false, nil
	}
	if readErr != nil {
		return 0, false, readErr
	}
	return length, true, nil
}

func h2FileSource(file *os.File) (h2PacketSource, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return h2PacketSource{}, err
	}
	var flags int
	var flagsErr error
	if err := raw.Control(func(fd uintptr) {
		flags, flagsErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil {
		return h2PacketSource{}, err
	}
	if flagsErr != nil {
		return h2PacketSource{}, flagsErr
	}
	if flags&unix.O_NONBLOCK == 0 {
		return h2PacketSource{}, errors.New("h2-output-nonblocking-required")
	}
	return h2PacketSource{
		read:  file.Read,
		ready: func(packet []byte) (int, bool, error) { return h2ReadyRead(raw, packet) },
	}, nil
}

func (p *peer) forwardH2Output(ctx context.Context, file *os.File, connection *h2Packets) error {
	source, err := h2FileSource(file)
	if err != nil {
		return err
	}
	pump := h2BatchPump{source: source, allow: func(packet []byte) bool { return p.allowedPacket(packet, false) }}
	return pump.run(ctx, connection, func(packet []byte) { p.countPacket(packet, false) })
}

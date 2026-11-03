package main

import (
	"syscall"
	"time"
)

func init() {
	udpPacerSleep = sleepUDPPacer
	udpPacerWaitKind = "kernel-nanosleep"
}

// Go's idle epoll wait rounds sub-millisecond timers up to a millisecond.
// Block only the sender's OS thread; the Go scheduler can run its receivers.
func sleepUDPPacer(delay time.Duration) {
	until := time.Now().Add(delay)
	for delay > 0 {
		requested := syscall.NsecToTimespec(int64(delay))
		err := syscall.Nanosleep(&requested, nil)
		if err == nil {
			return
		}
		if err != syscall.EINTR {
			panic("UDP pacer kernel wait failed")
		}
		delay = time.Until(until)
	}
}

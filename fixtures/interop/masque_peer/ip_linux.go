// Original guest-only forwarding adapter. RFC capsules and Context ID framing
// are consumed by the official MIT connect-ip-go library, not reimplemented.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sys/unix"
)

type ipTunnel struct {
	file        *os.File
	table       string
	family      string
	forwardPath string
	forward     []byte
	once        sync.Once
	peer        *peer
}

func networkCommand(input []byte, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	return cmd.Run() // No stdout/stderr containing configuration or addresses.
}

func (t *ipTunnel) Close() error {
	var result error
	t.once.Do(func() {
		// Closing the pollable descriptor first wakes both owned packet workers.
		if t.file.Close() != nil {
			result = errors.New("network-cleanup")
		}
		if err := networkCommand(nil, "nft", "destroy", "table", t.family, t.table); err != nil {
			result = errors.New("network-cleanup")
		}
		if os.WriteFile(t.forwardPath, t.forward, 0600) != nil {
			result = errors.New("network-cleanup")
		}
		if restored, err := os.ReadFile(t.forwardPath); err != nil || !bytes.Equal(restored, t.forward) {
			result = errors.New("network-cleanup")
		}
		t.peer.mu.Lock()
		t.peer.stats.NetworkCleanups++
		if result != nil {
			t.peer.stats.NetworkErrors++
		}
		t.peer.mu.Unlock()
	})
	return result
}

func (p *peer) openTunnel() (*ipTunnel, error) {
	client, e1 := netip.ParseAddr(p.config.ClientIP)
	peerIP, e2 := netip.ParseAddr(p.config.PeerIP)
	host, port, e3 := net.SplitHostPort(p.config.Origin)
	origin, e4 := netip.ParseAddr(host)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || client.Is4() != peerIP.Is4() || client.Is4() != origin.Is4() || port != "24500" ||
		!regexp.MustCompile(`^vole_masque_[0-9a-f]{12}$`).MatchString(p.config.NetworkTable) {
		return nil, errors.New("network-config")
	}
	if len(p.config.PressureTargets) == 0 && p.config.DNSOrigin != "" && p.config.DNSOrigin != net.JoinHostPort(host, "24553") {
		return nil, errors.New("network-config")
	}
	family, forwardPath, routeFamily := "ip", "/proc/sys/net/ipv4/ip_forward", "-4"
	if client.Is6() {
		family, forwardPath, routeFamily = "ip6", "/proc/sys/net/ipv6/conf/all/forwarding", "-6"
	}
	forward, err := os.ReadFile(forwardPath)
	if err != nil {
		return nil, errors.New("network-forward")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("network-tun")
	}
	name := "mq" + strconv.Itoa(os.Getpid())
	request, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, errors.New("network-tun")
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if unix.IoctlIfreq(fd, unix.TUNSETIFF, request) != nil {
		_ = unix.Close(fd)
		return nil, errors.New("network-tun")
	}
	// Register with Go's poller only after TUN attachment; an unattached fd
	// reports POLLERR, which can make later reads fail with "not pollable".
	file := os.NewFile(uintptr(fd), "owned-masque-tun")
	table := p.config.NetworkTable
	// Only authenticated packets for this run's exact owned targets are NATed.
	addresses := make([]string, 0, len(p.ipTargets))
	for _, address := range p.targetAddresses() {
		addresses = append(addresses, address.String())
	}
	rules := "create table " + family + " " + table + "\n" +
		"add chain " + family + " " + table + " postrouting { type nat hook postrouting priority srcnat; policy accept; }\n" +
		"add rule " + family + " " + table + " postrouting " + family + " saddr " + client.String() + " " + family + " daddr { " + strings.Join(addresses, ", ") + " }" +
		" oifname \"eth0\" snat to " + peerIP.String() + "\n"
	setup := func() error {
		// No kernel addresses or router solicitation belong to this client tunnel.
		if networkCommand(nil, "ip", "link", "set", name, "multicast", "off") != nil {
			return errors.New("network-link")
		}
		ipv6 := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
		disabled := []byte("1\n")
		if client.Is6() {
			disabled = []byte("0\n")
			if os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/addr_gen_mode", []byte("1\n"), 0600) != nil {
				return errors.New("network-ipv6")
			}
		}
		if os.WriteFile(ipv6, disabled, 0600) != nil {
			return errors.New("network-ipv6")
		}
		if actual, err := os.ReadFile(ipv6); err != nil || !bytes.Equal(actual, disabled) {
			return errors.New("network-ipv6")
		}
		mtu := "1280"
		if p.config.PMTUMTU != 0 {
			mtu = "1500"
		}
		if networkCommand(nil, "ip", "link", "set", name, "mtu", mtu, "up") != nil {
			return errors.New("network-link")
		}
		if networkCommand(nil, "ip", routeFamily, "route", "add", netip.PrefixFrom(client, client.BitLen()).String(), "dev", name) != nil {
			return errors.New("network-route")
		}
		if networkCommand([]byte(rules), "nft", "-f", "-") != nil {
			return errors.New("network-nat")
		}
		if os.WriteFile(forwardPath, []byte("1\n"), 0600) != nil {
			return errors.New("network-forward-write")
		}
		return nil
	}
	if err := setup(); err != nil {
		_ = file.Close() // Nonpersistent TUN removal also removes its source route.
		_ = networkCommand(nil, "nft", "destroy", "table", family, table)
		_ = os.WriteFile(forwardPath, forward, 0600)
		return nil, err
	}
	p.mu.Lock()
	p.stats.NetworkSessions++
	p.mu.Unlock()
	return &ipTunnel{file: file, table: table, family: family, forwardPath: forwardPath, forward: forward, peer: p}, nil
}

func (p *peer) rejectIP(w http.ResponseWriter, phase string) {
	p.mu.Lock()
	p.stats.ConnectRejected++
	p.stats.FailurePhase = phase
	p.mu.Unlock()
	w.WriteHeader(http.StatusForbidden)
}

func (p *peer) serveIP(w http.ResponseWriter, r *http.Request) {
	// Preserve actual wire validation before adapting the private protocol name.
	_, port, err := net.SplitHostPort(p.config.Listen)
	if err != nil || r.Method != http.MethodConnect || r.Proto != "cf-connect-ip" ||
		r.Host != net.JoinHostPort(p.config.PeerIP, port) || r.URL.Path != "/" {
		p.rejectIP(w, "connect-request")
		return
	}
	adapted := r.Clone(r.Context())
	adapted.Proto = "connect-ip"
	template := uritemplate.MustNew("https://" + r.Host + "/")
	parsed, err := connectip.ParseProxyRequest(adapted, template)
	if err != nil {
		p.rejectIP(w, "connect-parse")
		return
	}
	if !p.recordSettings(w, r) {
		p.rejectIP(w, "connect-settings")
		return
	}
	p.mu.Lock()
	if p.ipBusy || p.closed || p.draining {
		p.mu.Unlock()
		p.rejectIP(w, "connect-state")
		return
	}
	p.ipBusy = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.ipBusy = false
		p.mu.Unlock()
	}()
	tun, err := p.openTunnel()
	if err != nil {
		p.rejectIP(w, err.Error()) // openTunnel returns fixed public phase labels only.
		return
	}
	defer tun.Close()
	conn, err := (&connectip.Proxy{}).Proxy(w, parsed)
	if err != nil {
		return
	}
	stream := w.(http3.HTTPStreamer).HTTPStream()
	item := &flow{stream: stream, target: tun}
	if quicConn, ok := r.Context().Value(quicConnectionKey{}).(*quic.Conn); ok {
		item.cancel = func() {
			_ = quicConn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		}
	}
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		_ = conn.Close()
		return
	}
	p.active[item] = struct{}{}
	p.stats.ConnectAccepted++
	p.stats.CFConnectIP++
	p.mu.Unlock()
	p.snapshot()
	defer func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		_ = conn.Close()
		p.mu.Lock()
		delete(p.active, item)
		p.mu.Unlock()
	}()
	client := netip.MustParseAddr(p.config.ClientIP)
	routes := make([]connectip.IPRoute, 0, len(p.ipTargets))
	for _, address := range p.targetAddresses() {
		routes = append(routes, connectip.IPRoute{StartIP: address, EndIP: address, IPProtocol: 0})
	}
	if conn.AssignAddresses([]netip.Prefix{netip.PrefixFrom(client, client.BitLen())}) != nil ||
		conn.AdvertiseRoute(routes) != nil {
		return
	}
	p.mu.Lock()
	p.stats.Routes++
	p.mu.Unlock()
	p.forwardIP(r.Context(), tun, conn, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		_ = conn.Close()
	}, func(ctx context.Context) error {
		for {
			if _, err := conn.Routes(ctx); err != nil {
				return err
			}
		}
	})
}

type packetConnection interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
}

func (p *peer) forwardIP(parent context.Context, tun *ipTunnel, conn packetConnection, stop func(), watch func(context.Context) error) {
	timeout := 30 * time.Second
	if p.config.IPTunnelTimeoutSeconds != 0 {
		timeout = time.Duration(p.config.IPTunnelTimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	finished := make(chan struct{}, 3)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer func() { finished <- struct{}{} }()
		packet := make([]byte, 65536)
		for {
			n, err := conn.ReadPacket(packet)
			if err != nil {
				return
			}
			if !p.allowedPacket(packet[:n], true) {
				continue
			}
			if p.config.PMTUMTU != 0 {
				drop, feedback := p.pmtu.intercept(packet[:n], p.config.PMTUMTU, p.config.PMTUWitness)
				if feedback != nil {
					if icmp, err := conn.WritePacket(feedback); err != nil || len(icmp) != 0 {
						return
					}
				}
				if drop {
					continue
				}
			}
			written, err := tun.file.Write(packet[:n])
			if err != nil || written != n {
				return
			}
			p.countPacket(packet[:n], true)
		}
	}()
	go func() {
		defer workers.Done()
		defer func() { finished <- struct{}{} }()
		packet := make([]byte, 65536)
		for {
			n, err := tun.file.Read(packet)
			if err != nil {
				return
			}
			if !p.allowedPacket(packet[:n], false) {
				continue
			}
			icmp, err := conn.WritePacket(packet[:n])
			if err != nil {
				return
			}
			if len(icmp) != 0 {
				// The public library returns path feedback to its local sender.
				// Deliver it to the peer stack, as Mihomo's adapter does, rather
				// than closing the tunnel when a return packet exceeds QUIC MTU.
				if written, err := tun.file.Write(icmp); err != nil || written != len(icmp) {
					return
				}
				continue
			}
			p.countPacket(packet[:n], false)
		}
	}()
	if watch != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_ = watch(ctx)
			finished <- struct{}{}
		}()
	}
	select {
	case <-finished:
	case <-ctx.Done():
	}
	cancel()
	stop()
	_ = tun.Close()
	workers.Wait()
}

func (p *peer) allowedPacket(packet []byte, incoming bool) bool {
	client := netip.MustParseAddr(p.config.ClientIP)
	var source, target netip.Addr
	valid, offset, protocol, hops := false, 0, byte(0), byte(0)
	if client.Is4() && len(packet) >= 24 && packet[0]>>4 == 4 {
		source, target = netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20]))
		valid = int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
		offset, protocol, hops = int(packet[0]&15)*4, packet[9], packet[8]
		valid = valid && offset >= 20
	} else if client.Is6() && len(packet) >= 44 && packet[0]>>4 == 6 {
		source, target = netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40]))
		valid = int(binary.BigEndian.Uint16(packet[4:6]))+40 == len(packet)
		offset, protocol, hops = 40, packet[6], packet[7]
	}
	if valid {
		valid = offset+4 <= len(packet) && hops > 1 && (protocol == 6 || protocol == 17)
		if valid {
			remote, local := source, target
			if incoming {
				offset += 2
				remote, local = target, source
			}
			port := binary.BigEndian.Uint16(packet[offset : offset+2])
			valid = local == client && p.allowedPort(remote, port)
		}
	}
	if !valid {
		p.mu.Lock()
		p.stats.IPRejected++
		p.mu.Unlock()
	}
	return valid
}

func (p *peer) countPacket(packet []byte, incoming bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	protocol := packet[9]
	if packet[0]>>4 == 6 {
		protocol = packet[6]
	}
	if incoming {
		// Count authenticated packets after the strict owned source/route checks.
		// H3 public APIs use Context ID 0; H2 DATAGRAM capsules carry raw IP.
		if p.config.Network == "h2" {
			p.stats.CapsuleReceived++
		} else {
			p.stats.ContextReceived++
		}
		p.stats.BytesToOrigin += uint64(len(packet))
		if protocol == 6 {
			p.stats.IPTCPToOrigin++
		} else {
			p.stats.IPUDPToOrigin++
		}
	} else {
		// Each transport's public framing API writes packets without logging bytes.
		if p.config.Network == "h2" {
			p.stats.CapsuleSent++
		} else {
			p.stats.ContextSent++
		}
		p.stats.BytesFromOrigin += uint64(len(packet))
		if protocol == 6 {
			p.stats.IPTCPFromOrigin++
		} else {
			p.stats.IPUDPFromOrigin++
		}
	}
}

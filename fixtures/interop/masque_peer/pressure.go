// Owned pressure origins supplement the fixed interoperability origin. These
// targets are supplied by the container coordinator, never by a proxy request.
package main

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

func (c config) targetIPs() (map[netip.Addr]bool, error) {
	if len(c.PressureTargets) > 8 {
		return nil, errors.New("pressure-targets")
	}
	targets := make(map[netip.Addr]bool)
	host, _, err := net.SplitHostPort(c.Origin)
	if err != nil {
		return nil, errors.New("origin")
	}
	origin, err := netip.ParseAddr(host)
	if err != nil {
		return nil, errors.New("origin")
	}
	if len(c.PressureTargets) == 0 {
		targets[origin] = false
	} else {
		for name, address := range c.PressureTargets {
			ip, err := netip.ParseAddr(address)
			if err != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4() != origin.Is4() ||
				len(name) == 0 || len(name) > 253 || strings.ContainsAny(name, " /\\@?#%\r\n\t") {
				return nil, errors.New("pressure-targets")
			}
			if literal, err := netip.ParseAddr(name); err == nil && literal != ip {
				return nil, errors.New("pressure-targets")
			}
			targets[ip] = true
		}
		if !targets[origin] {
			return nil, errors.New("pressure-origin")
		}
	}
	if c.DNSOrigin != "" {
		host, port, err := net.SplitHostPort(c.DNSOrigin)
		ip, parseErr := netip.ParseAddr(host)
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || parseErr != nil || portErr != nil || portNumber == 0 || ip.Is4() != origin.Is4() ||
			(len(c.PressureTargets) == 0 && port != "24553") ||
			(len(c.PressureTargets) == 0 && ip != origin) ||
			(len(c.PressureTargets) > 0 && host != c.PeerIP) {
			return nil, errors.New("dns-origin")
		}
		if _, exists := targets[ip]; !exists {
			targets[ip] = false
		}
	}
	return targets, nil
}

func (p *peer) targetAddresses() []netip.Addr {
	result := make([]netip.Addr, 0, len(p.ipTargets))
	for ip := range p.ipTargets {
		result = append(result, ip)
	}
	slices.SortFunc(result, netip.Addr.Compare)
	return result
}

func (p *peer) allowedPort(ip netip.Addr, port uint16) bool {
	pressure, exists := p.ipTargets[ip]
	if !exists {
		return false
	}
	if len(p.config.PressureTargets) == 0 {
		return port == 24500 || p.config.DNSOrigin == net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	}
	if pressure {
		return port >= 1024 && port != 24003 // Never proxy workload control.
	}
	return p.config.DNSOrigin == net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func (p *peer) proxyTarget(authority string) (string, bool) {
	if authority == p.config.DNSOrigin && authority != "" {
		return authority, true
	}
	if len(p.config.PressureTargets) == 0 {
		return authority, authority == p.config.Origin
	}
	host, port, err := net.SplitHostPort(authority)
	value, portErr := strconv.ParseUint(port, 10, 16)
	ip, exists := p.config.PressureTargets[host]
	if err != nil || portErr != nil || !exists || !p.allowedPort(netip.MustParseAddr(ip), uint16(value)) {
		return "", false
	}
	return net.JoinHostPort(ip, port), true
}

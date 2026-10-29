package zeroconf

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type hostnameTransport struct {
	ipv4Ifaces, ipv6Ifaces, nativeIPv6 []net.Interface
	ipv6Indexes                        map[int]int
}

func hostnameInterfaces(opts clientOpts) ([]net.Interface, *hostnameTransport, error) {
	ifaces := opts.ifaces
	automatic := len(ifaces) == 0
	if automatic {
		ifaces = listMulticastInterfaces()
	}
	var selected []net.Interface
	t := new(hostnameTransport)
	for _, iface := range ifaces {
		if automatic && iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
		v4, v6 := interfaceFamilies(addresses)
		v4 = v4 && opts.listenOn&IPv4 != 0
		v6 = v6 && opts.listenOn&IPv6 != 0
		if !v4 && !v6 {
			if automatic {
				continue
			}
			return nil, nil, fmt.Errorf("no selected mDNS traffic family on interface %s (%d)", iface.Name, iface.Index)
		}
		if v4 {
			t.ipv4Ifaces = append(t.ipv4Ifaces, iface)
		}
		if v6 {
			t.ipv6Ifaces = append(t.ipv6Ifaces, iface)
		}
		selected = append(selected, iface)
	}
	if len(selected) == 0 {
		return nil, nil, fmt.Errorf("no usable multicast interface")
	}
	var err error
	if len(t.ipv6Ifaces) != 0 {
		t.nativeIPv6, t.ipv6Indexes, err = nativeIPv6Interfaces(t.ipv6Ifaces)
		if err != nil {
			return nil, nil, err
		}
	}
	return selected, t, nil
}

func (c *client) sendHostnamePacket(buf []byte) error {
	t := c.hostnameTransport
	if c.ipv4conn != nil {
		for _, iface := range t.ipv4Ifaces {
			if _, err := writeMulticast4(c.ipv4conn, buf, &ipv4.ControlMessage{IfIndex: iface.Index}, ipv4Addr); err != nil {
				return fmt.Errorf("send mDNS IPv4 on interface %d: %w", iface.Index, err)
			}
		}
	}
	if c.ipv6conn != nil {
		for _, iface := range t.ipv6Ifaces {
			if _, err := writeMulticast6(c.ipv6conn, buf, &ipv6.ControlMessage{IfIndex: iface.Index}, ipv6Addr, t.ipv6Indexes); err != nil {
				return fmt.Errorf("send mDNS IPv6 on interface %d: %w", iface.Index, err)
			}
		}
	}
	return nil
}

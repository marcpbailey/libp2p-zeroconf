//go:build !windows

package zeroconf

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func preparePacket4(c *ipv4.PacketConn) error { return c.SetControlMessage(ipv4.FlagInterface, true) }
func preparePacket6(c *ipv6.PacketConn) error { return c.SetControlMessage(ipv6.FlagInterface, true) }
func nativeIPv6Interfaces(ifaces []net.Interface) ([]net.Interface, map[int]int, error) {
	return ifaces, nil, nil
}
func readMulticast4(c *ipv4.PacketConn, b []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	return c.ReadFrom(b)
}
func readMulticast6(c *ipv6.PacketConn, b []byte, indexes map[int]int) (int, *ipv6.ControlMessage, net.Addr, error) {
	return c.ReadFrom(b)
}
func writeMulticast4(c *ipv4.PacketConn, b []byte, cm *ipv4.ControlMessage, to net.Addr) (int, error) {
	return c.WriteTo(b, cm, to)
}
func writeMulticast6(c *ipv6.PacketConn, b []byte, cm *ipv6.ControlMessage, to net.Addr, indexes map[int]int) (int, error) {
	return c.WriteTo(b, cm, to)
}

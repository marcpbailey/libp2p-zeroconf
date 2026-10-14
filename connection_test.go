package zeroconf

import (
	"net"
	"reflect"
	"testing"
)

func TestAutomaticInterfaceSelectionSkipsInterfacesWithoutAddresses(t *testing.T) {
	anpi0 := net.Interface{Index: 4, Name: "anpi0", Flags: net.FlagUp | net.FlagMulticast}
	en0 := net.Interface{Index: 5, Name: "en0", Flags: net.FlagUp | net.FlagMulticast}
	down := net.Interface{Index: 6, Name: "down0", Flags: net.FlagMulticast}
	nonMulticast := net.Interface{Index: 7, Name: "ethernet0", Flags: net.FlagUp}
	interfaces := []net.Interface{anpi0, en0, down, nonMulticast}
	addresses := map[int][]net.Addr{
		// anpi0 is UP and MULTICAST but has no address, matching the reported
		// inactive interface that made automatic registration fail.
		en0.Index: {&net.IPNet{IP: net.ParseIP("172.17.17.157")}},
	}

	got := eligibleMulticastInterfaces(interfaces, func(iface net.Interface) ([]net.Addr, error) {
		return addresses[iface.Index], nil
	})
	if !reflect.DeepEqual(got, []net.Interface{en0}) {
		t.Fatalf("automatic interfaces = %#v, want only %#v", got, en0)
	}
}

func TestAutomaticInterfaceSelectionSkipsLoopbackAndPointToPoint(t *testing.T) {
	loopback := net.Interface{Index: 8, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback | net.FlagMulticast}
	tunnel := net.Interface{Index: 9, Name: "utun3", Flags: net.FlagUp | net.FlagPointToPoint | net.FlagMulticast}
	ethernet := net.Interface{Index: 10, Name: "en0", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast}
	bridge := net.Interface{Index: 11, Name: "bridge100", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast}
	interfaces := []net.Interface{loopback, tunnel, ethernet, bridge}
	addresses := map[int][]net.Addr{
		loopback.Index: {&net.IPNet{IP: net.ParseIP("127.0.0.1")}},
		tunnel.Index:   {&net.IPNet{IP: net.ParseIP("fe80::1")}},
		ethernet.Index: {&net.IPNet{IP: net.ParseIP("192.0.2.10")}},
		bridge.Index:   {&net.IPNet{IP: net.ParseIP("192.0.2.11")}},
	}

	got := eligibleMulticastInterfaces(interfaces, func(iface net.Interface) ([]net.Addr, error) {
		return addresses[iface.Index], nil
	})
	want := []net.Interface{ethernet, bridge}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("automatic interfaces = %#v, want %#v", got, want)
	}
}

func TestAutomaticInterfacesKeepCandidatesWithJoinedTransports(t *testing.T) {
	failed := net.Interface{Index: 12, Name: "failed"}
	ipv4 := net.Interface{Index: 13, Name: "ipv4"}
	ipv6 := net.Interface{Index: 14, Name: "ipv6"}
	got := interfacesWithTransport(
		[]net.Interface{failed, ipv4, ipv6},
		[]net.Interface{ipv4},
		[]net.Interface{ipv6},
	)
	want := []net.Interface{ipv4, ipv6}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("automatic interfaces with joined transports = %#v, want %#v", got, want)
	}
}

func TestExplicitInterfaceSelectionRemainsSupported(t *testing.T) {
	iface := testMulticastIfaces(t)[0]
	server, err := RegisterProxy(
		"explicit-interface-test", "_zeroconf-test._tcp", "local.", 8888,
		"explicit-interface-test.local.", []string{"192.0.2.10"}, nil,
		[]net.Interface{iface},
	)
	if err != nil {
		t.Fatalf("register with explicitly selected interface: %v", err)
	}
	defer server.Shutdown()

	if len(server.ifaces) != 1 || server.ifaces[0].Index != iface.Index {
		t.Fatalf("registered interfaces = %#v, want explicit interface %#v", server.ifaces, iface)
	}
}

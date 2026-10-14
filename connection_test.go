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

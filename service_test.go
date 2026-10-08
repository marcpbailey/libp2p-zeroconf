package zeroconf

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

var (
	mdnsName    = "test--xxxxxxxxxxxx"
	mdnsService = "_test--xxxx._tcp"
	mdnsSubtype = "_test--xxxx._tcp,_fancy"
	mdnsDomain  = "local."
	mdnsPort    = 8888
)

func startMDNS(t *testing.T, port int, name, service, domain string) {
	// 5353 is default mdns port
	server, err := registerTestService(t, name, service, domain, port, []string{"txtv=0", "lo=1", "la=2"})
	if err != nil {
		t.Fatalf("error while registering mdns service: %s", err)
	}
	t.Cleanup(server.Shutdown)
	log.Printf("Published service: %s, type: %s, domain: %s", name, service, domain)
}

func TestQuickShutdown(t *testing.T) {
	server, err := registerTestService(t, mdnsName, mdnsService, mdnsDomain, mdnsPort, []string{"txtv=0", "lo=1", "la=2"})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Shutdown()
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("shutdown took longer than 500ms")
	}
}

func TestBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startMDNS(t, mdnsPort, mdnsName, mdnsService, mdnsDomain)

	time.Sleep(time.Second)

	entries := make(chan *ServiceEntry, 100)
	if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
		t.Fatalf("Expected browse success, but got %v", err)
	}
	<-ctx.Done()

	if len(entries) != 1 {
		t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
	}
	result := <-entries
	if result.Domain != mdnsDomain {
		t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
	}
	if result.Service != mdnsService {
		t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
	}
	if result.Instance != mdnsName {
		t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
	}
	if result.Port != mdnsPort {
		t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
	}
}

func TestNoRegister(t *testing.T) {
	// before register, mdns resolve shuold not have any entry
	entries := make(chan *ServiceEntry)
	go func(results <-chan *ServiceEntry) {
		s := <-results
		if s != nil {
			t.Errorf("Expected empty service entries but got %v", *s)
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
		t.Fatalf("Expected browse success, but got %v", err)
	}
	<-ctx.Done()
	cancel()
}

func TestSubtype(t *testing.T) {
	t.Run("browse with subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		time.Sleep(time.Second)

		entries := make(chan *ServiceEntry, 100)
		if err := Browse(ctx, mdnsSubtype, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}
		<-ctx.Done()

		if len(entries) != 1 {
			t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})

	t.Run("browse without subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		time.Sleep(time.Second)

		entries := make(chan *ServiceEntry, 100)
		if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}
		<-ctx.Done()

		if len(entries) != 1 {
			t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})

	t.Run("ttl", func(t *testing.T) {
		origTTL := defaultTTL
		origCleanupFreq := cleanupFreq
		origInitialQueryInterval := initialQueryInterval
		t.Cleanup(func() {
			defaultTTL = origTTL
			cleanupFreq = origCleanupFreq
			initialQueryInterval = origInitialQueryInterval
		})
		defaultTTL = 1 // 1 second
		initialQueryInterval = 100 * time.Millisecond
		cleanupFreq = 100 * time.Millisecond

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		entries := make(chan *ServiceEntry, 100)
		if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}

		<-ctx.Done()
		if len(entries) < 2 {
			t.Fatalf("Expected to have received at least 2 entries, but got %d", len(entries))
		}
		res1 := <-entries
		res2 := <-entries
		if res1.ServiceInstanceName() != res2.ServiceInstanceName() {
			t.Fatalf("expected the two entries to be identical")
		}
	})
}

// Multicast integration tests use private groups and a test port on one
// interface, and never claim the computer's hostname.
func testMulticastIfaces(t *testing.T) []net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 {
			addresses, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, address := range addresses {
				if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP.To4() != nil && ipnet.IP.IsGlobalUnicast() {
					return []net.Interface{iface}
				}
			}
		}
	}
	t.Skip("no active IPv4 multicast interface")
	return nil
}

func registerTestService(t *testing.T, instance, service, domain string, port int, text []string) (*Server, error) {
	t.Helper()
	host := fmt.Sprintf("zeroconf-test-%d-%d.local.", os.Getpid(), time.Now().UnixNano())
	return RegisterProxy(instance, service, domain, port, host, []string{"127.0.0.1"}, text, testMulticastIfaces(t))
}

// Use private test destinations and multicast bindings, never the system mDNS
// port or multicast groups. The protocol processing remains unchanged.
func TestMain(m *testing.M) {
	if os.Getenv("ZEROCONF_INTEROP_INTERFACE") != "" {
		flag.Parse()
		run := flag.Lookup("test.run").Value.String()
		if run != "^TestNativeInterop$" && run != "^TestBonjourRemotePeer$" && run != "^TestBonjourDefenceTiming$" {
			fmt.Fprintln(os.Stderr, "interop requires an exact test name; refusing default tests on native mDNS")
			os.Exit(2)
		}
		os.Exit(m.Run())
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	listener.Close()
	mdnsGroupIPv4 = net.ParseIP("239.255.42.33")
	mdnsGroupIPv6 = net.ParseIP("ff02::114")
	mdnsWildcardAddrIPv4 = &net.UDPAddr{IP: mdnsGroupIPv4, Port: port}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{IP: net.ParseIP("ff02::"), Port: port}
	ipv4Addr = &net.UDPAddr{IP: mdnsGroupIPv4, Port: port}
	ipv6Addr = &net.UDPAddr{IP: mdnsGroupIPv6, Port: port}
	os.Exit(m.Run())
}

func TestBrowseDoesNotEmitTentativeProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entries := make(chan *ServiceEntry, 10)
	results := make(chan error, 1)
	cl, err := newClient(applyOpts(SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)))
	if err != nil {
		t.Fatal(err)
	}
	params := defaultParams("_tentative._tcp")
	params.Domain = "local."
	params.Entries = entries
	params.isBrowsing = true
	go func() { results <- cl.run(ctx, params) }()
	server, err := registerTestService(t, "tentative", "_tentative._tcp", "local.", 9000, []string{"v=1"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	select {
	case entry := <-entries:
		if entry == nil {
			t.Fatal("browse closed without an established result")
		}
		server.mu.Lock()
		ready := server.readySet && server.readyErr == nil
		server.mu.Unlock()
		if !ready {
			t.Error("browse emitted a tentative probe as an established registration")
		}
	case <-ctx.Done():
		t.Error("no established browse result")
	}
	cancel()
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

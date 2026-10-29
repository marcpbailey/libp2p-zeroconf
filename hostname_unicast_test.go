package zeroconf

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestHostnameTransportChoice(t *testing.T) {
	for _, test := range []struct {
		name    string
		mode    HostnameTransport
		options []ClientOption
		want    HostnameTransport
		invalid bool
	}{
		{name: "host.local", want: HostnameMulticast},
		{name: "HOST.LOCAL.", want: HostnameMulticast},
		{name: "host.example.test", want: HostnameUnicast},
		{name: "host.example.test", mode: HostnameMulticast, want: HostnameMulticast},
		{name: "host.local", mode: HostnameUnicast, want: HostnameUnicast},
		{name: "host.local", options: []ClientOption{UnicastDNS("192.0.2.53")}, want: HostnameUnicast},
		{name: "host.example.test", mode: HostnameMulticast, options: []ClientOption{UnicastDNS()}, invalid: true},
		{name: "host.example.test", mode: 9, invalid: true},
	} {
		q, err := normalizeHostnameQuery(HostnameQuery{Name: test.name, Transport: test.mode})
		if err == nil {
			var mode HostnameTransport
			mode, err = hostnameLookupTransport(q, applyOpts(test.options...))
			if err == nil && mode != test.want {
				t.Errorf("%+v: mode %d", test, mode)
			}
		}
		if (err != nil) != test.invalid {
			t.Errorf("%+v: %v", test, err)
		}
	}
}

func TestHostnameUnicastFamiliesAndTTLs(t *testing.T) {
	for _, family := range []IPType{IPv4, IPv6, IPv4AndIPv6} {
		s := startDNSServer(t)
		s.set(t, testHost, dns.TypeA, testHost+" 12 IN A 192.0.2.10", testHost+" 30 IN A 192.0.2.11")
		s.set(t, testHost, dns.TypeAAAA, testHost+" 60 IN AAAA 2001:db8::10")
		got, err := LookupHostname(context.Background(), HostnameQuery{Name: "HOST.EXAMPLE.TEST", Families: family}, UnicastDNS(s.address))
		if err != nil || len(got) != 1 {
			t.Fatalf("family %d: %+v, %v", family, got, err)
		}
		if got[0].Transport != HostnameUnicast || got[0].InterfaceIndex != 0 || got[0].Name != testHost {
			t.Fatalf("scope: %+v", got[0])
		}
		want := 3
		if family == IPv4 {
			want = 2
		}
		if family == IPv6 {
			want = 1
		}
		if len(got[0].Addresses) != want {
			t.Fatalf("addresses: %+v", got)
		}
		for _, a := range got[0].Addresses {
			if a.Name != testHost || a.TTL == 0 || a.Expiry.Before(time.Now()) {
				t.Fatalf("record: %+v", a)
			}
		}
		s.mu.Lock()
		for _, q := range s.queries {
			if family == IPv4 && q.Qtype != dns.TypeA || family == IPv6 && q.Qtype != dns.TypeAAAA {
				t.Errorf("unexpected question: %+v", q)
			}
		}
		s.mu.Unlock()
	}
}

func TestHostnameUnicastNegativesAndErrors(t *testing.T) {
	for _, test := range []struct {
		name               string
		rcode              int
		incomplete, silent bool
	}{
		{name: "nodata"}, {name: "nxdomain", rcode: dns.RcodeNameError},
		{name: "servfail", rcode: dns.RcodeServerFailure}, {name: "incomplete", incomplete: true}, {name: "timeout", silent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := startDNSServer(t)
			s.mu.Lock()
			s.rcode = test.rcode
			s.incomplete = test.incomplete
			s.silent = test.silent
			s.mu.Unlock()
			got, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost, Duration: 50 * time.Millisecond}, UnicastDNS(s.address))
			negative := test.name == "nodata" || test.name == "nxdomain"
			if negative {
				if err != nil || len(got) != 1 || len(got[0].NoData) != 2 {
					t.Fatalf("negative: %+v, %v", got, err)
				}
				for _, n := range got[0].NoData {
					if n.NXDOMAIN != (test.rcode == dns.RcodeNameError) || n.TTL != 1 {
						t.Fatalf("negative metadata: %+v", n)
					}
				}
			} else if err == nil || len(got) != 0 {
				t.Fatalf("failure became a negative: %+v, %v", got, err)
			}
		})
	}
	// One family's explicit absence must not suppress the other family's addresses.
	s := startDNSServer(t)
	s.set(t, testHost, dns.TypeA, testHost+" 10 IN A 192.0.2.10")
	got, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost}, UnicastDNS(s.address))
	if err != nil || len(got) != 1 || len(got[0].Addresses) != 1 || len(got[0].NoData) != 1 || got[0].NoData[0].Family != IPv6 {
		t.Fatalf("partial dual stack: %+v, %v", got, err)
	}
}

func TestHostnameUnicastCNAMEAndTCP(t *testing.T) {
	s := startDNSServer(t)
	s.mu.Lock()
	s.truncate = true
	s.mu.Unlock()
	s.set(t, testHost, dns.TypeA, testHost+" 5 IN CNAME target.example.test.")
	s.set(t, "target.example.test.", dns.TypeA, "target.example.test. 60 IN A 192.0.2.10")
	got, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost, Families: IPv4}, UnicastDNS(s.address))
	if err != nil || len(got) != 1 || len(got[0].Addresses) != 1 {
		t.Fatalf("alias: %+v, %v", got, err)
	}
	a := got[0].Addresses[0]
	if a.Name != "target.example.test." || a.TTL != 60 || time.Until(a.Expiry) > 5*time.Second {
		t.Fatalf("alias lifetime: %+v", a)
	}
	s.mu.Lock()
	tcp := s.tcpQueries
	s.mu.Unlock()
	if tcp < 2 {
		t.Fatalf("TCP fallback: %d", tcp)
	}
	s.set(t, "target.example.test.", dns.TypeA, "target.example.test. 10 IN CNAME host.example.test.")
	if _, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost, Families: IPv4}, UnicastDNS(s.address)); err == nil {
		t.Fatal("accepted CNAME loop")
	}
}

func TestHostnameUnicastCancellationAndOptions(t *testing.T) {
	s := startDNSServer(t)
	s.mu.Lock()
	s.silent = true
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := LookupHostname(ctx, HostnameQuery{Name: testHost}, UnicastDNS(s.address)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	for _, options := range [][]ClientOption{
		{UnicastDNS("not-a-server")},
		{UnicastDNS(s.address), SelectIfaces([]net.Interface{{Index: 1}})},
		{UnicastDNS(s.address), SelectIPTraffic(IPv4)},
		{UnicastDNS(s.address), Unannouncements()},
	} {
		if _, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost}, options...); err == nil {
			t.Fatal("accepted invalid unicast options")
		}
	}
}

func TestHostnameUnicastFailoverEDNSAndScope(t *testing.T) {
	bad, good := startDNSServer(t), startDNSServer(t)
	bad.mu.Lock()
	bad.rcode = dns.RcodeServerFailure
	bad.mu.Unlock()
	good.mu.Lock()
	good.rejectEDNS = true
	good.mu.Unlock()
	good.set(t, testHost, dns.TypeA, testHost+" 20 IN A 192.0.2.10", testHost+" 30 IN A 192.0.2.10")
	got, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost, Families: IPv4}, UnicastDNS(bad.address, good.address))
	if err != nil || len(got) != 1 || len(got[0].Addresses) != 1 || got[0].Addresses[0].TTL != 20 {
		t.Fatalf("failover/EDNS/deduplication: %+v, %v", got, err)
	}
	good.set(t, testHost, dns.TypeAAAA, testHost+" 10 IN AAAA fe80::10")
	if _, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost, Families: IPv6}, UnicastDNS(good.address)); err == nil {
		t.Fatal("accepted unscoped link-local DNS address")
	}
	good.set(t, "host.local.", dns.TypeA, "host.local. 10 IN A 192.0.2.10")
	got, err = LookupHostname(context.Background(), HostnameQuery{Name: "host.local", Families: IPv4}, UnicastDNS(good.address))
	if err != nil || len(got) != 1 || got[0].Transport != HostnameUnicast {
		t.Fatalf("explicit unicast local override: %+v, %v", got, err)
	}
}

func TestHostnameUnicastPartialFailureAndCancellation(t *testing.T) {
	ready := make(chan struct{}, 1)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		if m.Question[0].Qtype == dns.TypeAAAA {
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(m)
		reply.Answer = []dns.RR{rr(t, testHost+" 30 IN A 192.0.2.10")}
		w.WriteMsg(reply)
		select {
		case ready <- struct{}{}:
		default:
		}
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	<-started
	t.Cleanup(func() { server.Shutdown() })
	for _, cancelCall := range []bool{false, true} {
		select {
		case <-ready:
		default:
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		if cancelCall {
			go func() { defer close(done); <-ready; time.Sleep(10 * time.Millisecond); cancel() }()
		} else {
			close(done)
		}
		got, err := LookupHostname(ctx, HostnameQuery{Name: testHost, Duration: 100 * time.Millisecond}, UnicastDNS(udp.LocalAddr().String()))
		cancel()
		<-done
		want := context.DeadlineExceeded
		if cancelCall {
			want = context.Canceled
		}
		if !errors.Is(err, want) || len(got) != 1 || len(got[0].Addresses) != 1 || len(got[0].NoData) != 0 {
			t.Fatalf("partial result: %+v, %v", got, err)
		}
	}
}

func TestHostnameUnicastConcurrentCalls(t *testing.T) {
	s := startDNSServer(t)
	s.set(t, testHost, dns.TypeA, testHost+" 30 IN A 192.0.2.10")
	done := make(chan error, 4)
	for n := 0; n < 4; n++ {
		go func() {
			got, err := LookupHostname(context.Background(), HostnameQuery{Name: testHost}, UnicastDNS(s.address))
			if err == nil && (len(got) != 1 || len(got[0].Addresses) != 1 || len(got[0].NoData) != 1) {
				err = errors.New("missing concurrent DNS result")
			}
			done <- err
		}()
	}
	for n := 0; n < 4; n++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

// Model a context timer whose notification is delayed after its deadline. The
// socket deadline can fire first on a busy host without changing the API error.
type delayedHostnameDeadline struct {
	context.Context
	deadline time.Time
}

func (c delayedHostnameDeadline) Deadline() (time.Time, bool) { return c.deadline, true }

func TestHostnameDNSDeadlineBeforeContextNotification(t *testing.T) {
	s := startDNSServer(t)
	s.mu.Lock()
	s.silent = true
	s.mu.Unlock()
	ctx := delayedHostnameDeadline{Context: context.Background(), deadline: time.Now().Add(20 * time.Millisecond)}
	message := new(dns.Msg)
	message.SetQuestion(testHost, dns.TypeA)
	_, err := exchangeDNS(ctx, message, s.address, "udp")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline without context notification: %v", err)
	}
}

func TestHostnameUnicastAliasesInOnePacket(t *testing.T) {
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
	m.SetQuestion(testHost, dns.TypeA)
	m.Answer = []dns.RR{rr(t, testHost+" 5 IN CNAME canonical.example.test."), rr(t, "canonical.example.test. 30 IN A 192.0.2.10")}
	q := m.Question[0]
	a, name, expiry, next, err := parseHostnameDNS(m, q, time.Now(), false)
	if err != nil || next || a == nil || len(a.records) != 1 || name != "canonical.example.test." || time.Until(expiry) > 5*time.Second {
		t.Fatalf("same-packet alias: %s %v %v", name, next, err)
	}
	m.Answer = []dns.RR{rr(t, testHost+" 5 IN CNAME host.local.")}
	if _, _, _, _, err := parseHostnameDNS(m, q, time.Now(), false); err == nil {
		t.Fatal("automatic DNS alias into .local accepted")
	}
}

package zeroconf

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

func hostnameRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func hostnameMessage(t *testing.T, records ...string) *dns.Msg {
	t.Helper()
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}}
	for _, record := range records {
		m.Answer = append(m.Answer, hostnameRR(t, record))
	}
	// Exercise actual DNS wire encoding/decoding without network timing.
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var decoded dns.Msg
	if err := decoded.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return &decoded
}

func TestHostnameQuestions(t *testing.T) {
	for _, family := range []IPType{IPv4, IPv6, IPv4AndIPv6} {
		query, err := normalizeHostnameQuery(HostnameQuery{Name: "API.Dev.Example.LOCAL", Families: family})
		if err != nil {
			t.Fatal(err)
		}
		msg := hostnameQuestion(query)
		var got []uint16
		for _, q := range msg.Question {
			if q.Name != "api.dev.example.local." || q.Qclass != dns.ClassINET {
				t.Fatalf("question: %+v", q)
			}
			got = append(got, q.Qtype)
		}
		var want []uint16
		if family&IPv4 != 0 {
			want = append(want, dns.TypeA)
		}
		if family&IPv6 != 0 {
			want = append(want, dns.TypeAAAA)
		}
		if !reflect.DeepEqual(got, want) || msg.RecursionDesired {
			t.Fatalf("query: %s", msg)
		}
	}
}

func TestHostnameSplitPacketsAndInterfaces(t *testing.T) {
	now := time.Unix(100, 0)
	q := HostnameQuery{Name: "api.dev.example.local.", Families: IPv4AndIPv6}
	a := newHostnameAnswers(q, []net.Interface{{Index: 2, Name: "link2"}, {Index: 3, Name: "link3"}})
	a.accept(hostnameMessage(t, "API.Dev.Example.local. 120 IN A 192.0.2.10"), 2, now)
	a.accept(hostnameMessage(t, "api.dev.example.local. 60 IN AAAA fe80::10"), 2, now.Add(time.Millisecond))
	a.accept(hostnameMessage(t, "api.dev.example.local. 90 IN A 192.0.2.10", "api.dev.example.local. 30 IN A 192.0.2.11"), 2, now.Add(time.Second))
	a.accept(hostnameMessage(t, "api.dev.example.local. 45 IN A 192.0.2.10"), 3, now)
	got := a.snapshot(now.Add(2 * time.Second))
	if len(got) != 2 || got[0].InterfaceIndex != 2 || len(got[0].Addresses) != 3 || got[1].InterfaceIndex != 3 {
		t.Fatalf("results: %+v", got)
	}
	if got[0].Addresses[0].TTL != 90 || !got[0].Addresses[0].Expiry.Equal(now.Add(91*time.Second)) {
		t.Fatalf("TTL renewal: %+v", got[0])
	}
	if got[0].Addresses[2].IP.String() != "fe80::10" {
		t.Fatalf("link-local: %+v", got[0])
	}
	got[0].Addresses[0].IP[0] = 0
	if a.snapshot(now.Add(2 * time.Second))[0].Addresses[0].IP.String() != "192.0.2.10" {
		t.Fatal("result aliases lookup state")
	}
}

func TestHostnameFiltering(t *testing.T) {
	now := time.Unix(100, 0)
	for _, family := range []IPType{IPv4, IPv6} {
		a := newHostnameAnswers(HostnameQuery{Name: "host.local.", Families: family}, []net.Interface{{Index: 2}})
		m := hostnameMessage(t, "host.local. 10 IN A 192.0.2.10", "host.local. 10 IN AAAA 2001:db8::10", "unrelated.local. 10 IN A 192.0.2.20", "host.local. 10 CH A 192.0.2.30", "host.local. 10 IN A 0.0.0.0", "host.local. 10 IN AAAA ::ffff:192.0.2.40")
		a.accept(m, 0, now)
		a.accept(m, 3, now)
		if len(a.snapshot(now)) != 0 {
			t.Fatal("accepted missing or unselected interface")
		}
		m.Response = false
		a.accept(m, 2, now)
		m.Response = true
		m.Rcode = dns.RcodeNameError
		a.accept(m, 2, now)
		m.Rcode = dns.RcodeSuccess
		m.Opcode = dns.OpcodeUpdate
		a.accept(m, 2, now)
		m.Opcode = dns.OpcodeQuery
		m.Ns, m.Answer = m.Answer, nil
		a.accept(m, 2, now)
		if len(a.snapshot(now)) != 0 {
			t.Fatal("accepted query, error, opcode or authority records")
		}
		m.Extra, m.Ns = m.Ns, nil
		a.accept(m, 2, now)
		got := a.snapshot(now)
		if len(got) != 1 || len(got[0].Addresses) != 1 {
			t.Fatalf("family %d: %+v", family, got)
		}
	}
}

func TestHostnameNSEC(t *testing.T) {
	now := time.Unix(100, 0)
	a := newHostnameAnswers(HostnameQuery{Name: "host.local.", Families: IPv4AndIPv6}, []net.Interface{{Index: 2}})
	// RFC 6762 section 6.1 requires processing an unexpected NextDomain.
	a.accept(hostnameMessage(t, "host.local. 30 IN NSEC other.local. A", "host.local. 60 IN A 192.0.2.1"), 2, now)
	got := a.snapshot(now)
	if len(got) != 1 || len(got[0].NoData) != 1 || got[0].NoData[0].Family != IPv6 || got[0].NoData[0].TTL != 30 {
		t.Fatalf("partial dual-stack: %+v", got)
	}
	a.accept(hostnameMessage(t, "host.local. 60 IN AAAA 2001:db8::1"), 2, now.Add(time.Second))
	if len(a.snapshot(now.Add(time.Second))[0].NoData) != 0 {
		t.Fatal("positive answer did not replace negative")
	}
	b := newHostnameAnswers(a.query, a.ifaces)
	b.accept(hostnameMessage(t, "host.local. 30 IN NSEC host.local. NSEC"), 2, now)
	if len(b.snapshot(now)) != 0 {
		t.Fatal("accepted unicast-style NSEC")
	}
	b.accept(hostnameMessage(t, "host.local. 1 IN NSEC host.local. TXT"), 2, now)
	if len(b.snapshot(now)[0].NoData) != 2 || len(b.snapshot(now.Add(time.Second))) != 0 {
		t.Fatal("negative family or expiry")
	}
}

func TestHostnameRecordLifetime(t *testing.T) {
	now := time.Unix(100, 0)
	a := newHostnameAnswers(HostnameQuery{Name: "host.local.", Families: IPv4}, []net.Interface{{Index: 2}})
	a.accept(hostnameMessage(t, "host.local. 120 IN A 192.0.2.1"), 2, now)
	flush := hostnameMessage(t, "host.local. 120 IN A 192.0.2.2")
	flush.Answer[0].Header().Class |= qClassCacheFlush
	a.accept(flush, 2, now.Add(2*time.Second))
	if len(a.snapshot(now.Add(2500 * time.Millisecond))[0].Addresses) != 2 {
		t.Fatal("cache flush omitted one-second grace")
	}
	if len(a.snapshot(now.Add(3 * time.Second))[0].Addresses) != 1 {
		t.Fatal("cache flush retained stale address")
	}
	// A split RRset within one second must survive the flush.
	a.accept(hostnameMessage(t, "host.local. 120 IN A 192.0.2.3"), 2, now.Add(3100*time.Millisecond))
	a.accept(flush, 2, now.Add(3200*time.Millisecond))
	if len(a.snapshot(now.Add(4500 * time.Millisecond))[0].Addresses) != 2 {
		t.Fatal("split RRset lost")
	}
	a.accept(hostnameMessage(t, "host.local. 0 IN A 192.0.2.3"), 2, now.Add(5*time.Second))
	if len(a.snapshot(now.Add(5500 * time.Millisecond))[0].Addresses) != 2 {
		t.Fatal("goodbye omitted one-second grace")
	}
	a.accept(hostnameMessage(t, "host.local. 10 IN A 192.0.2.3"), 2, now.Add(5600*time.Millisecond))
	if len(a.snapshot(now.Add(7 * time.Second))[0].Addresses) != 2 {
		t.Fatal("cooperating answer failed to rescue goodbye")
	}
	if len(a.snapshot(now.Add(16 * time.Second))[0].Addresses) != 1 {
		t.Fatal("individual TTL not expired")
	}
}

func TestHostnameValidationAndCancellation(t *testing.T) {
	for _, name := range []string{"", "local.", "example.com", "host..local", "host.local..", "bad name.local", "-bad.local", "bad_.local", "host\\046label.local"} {
		if _, err := normalizeHostnameQuery(HostnameQuery{Name: name}); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, q := range []HostnameQuery{{Name: "host.local", Families: 8}, {Name: "host.local", Duration: -1}} {
		if _, err := normalizeHostnameQuery(q); err == nil {
			t.Errorf("accepted %+v", q)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LookupHostname(ctx, HostnameQuery{Name: "host.local"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := LookupHostname(context.Background(), HostnameQuery{Name: "host.local"}, func(o *clientOpts) { o.unicast = true }); err == nil {
		t.Fatal("accepted unicast")
	}
	if _, err := LookupHostname(context.Background(), HostnameQuery{Name: "host.local"}, Unannouncements()); err == nil {
		t.Fatal("accepted subscription removal option")
	}
}

func startHostnameResponder(t *testing.T, ifaces []net.Interface, answer func(*dns.Msg) *dns.Msg) {
	t.Helper()
	conn, err := joinUdp4Multicast(ifaces, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := preparePacket4(conn); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	c := &client{ipv4conn: conn, ifaces: ifaces, hostnameTransport: &hostnameTransport{ipv4Ifaces: ifaces}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.receive(ctx, conn, func(query *dns.Msg, index int, _ net.Addr) bool {
			if query.Response {
				return true
			}
			response := answer(query)
			if response == nil {
				return true
			}
			// Separate packets exercise address assembly without any service records.
			for _, rr := range response.Answer {
				msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: []dns.RR{rr}}
				wire, err := msg.Pack()
				if err != nil {
					return false
				}
				if _, err := writeMulticast4(conn, wire, &ipv4.ControlMessage{IfIndex: index}, ipv4Addr); err != nil {
					return false
				}
			}
			return true
		})
	}()
	t.Cleanup(func() { cancel(); conn.Close(); <-done })
}

func TestHostnameControlledMulticast(t *testing.T) {
	ifaces := testMulticastIfaces(t)
	startHostnameResponder(t, ifaces, func(query *dns.Msg) *dns.Msg {
		if len(query.Question) == 0 {
			return nil
		}
		name := query.Question[0].Name
		m := new(dns.Msg)
		if name != "single.local." && name != "api.dev.example.local." && name != "negative.local." {
			return nil
		}
		for _, q := range query.Question {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, hostnameRR(t, name+" 120 IN A 192.0.2.10"))
			case dns.TypeAAAA:
				if name == "negative.local." {
					m.Answer = append(m.Answer, hostnameRR(t, name+" 60 IN NSEC "+name+" A"))
				} else {
					m.Answer = append(m.Answer, hostnameRR(t, name+" 90 IN AAAA fe80::10"))
				}
			default:
				t.Errorf("hostname lookup emitted service question: %+v", q)
			}
		}
		return m
	})
	for _, name := range []string{"single.local", "API.Dev.Example.LOCAL."} {
		for _, family := range []IPType{IPv4, IPv6, IPv4AndIPv6} {
			got, err := LookupHostname(context.Background(), HostnameQuery{Name: name, Families: family, Duration: 150 * time.Millisecond}, SelectIfaces(ifaces), SelectIPTraffic(IPv4))
			if err != nil {
				t.Fatalf("%s family %d: %v", name, family, err)
			}
			count := 1
			if family == IPv4AndIPv6 {
				count = 2
			}
			if len(got) != 1 || len(got[0].Addresses) != count || got[0].InterfaceIndex != ifaces[0].Index {
				t.Fatalf("%s family %d: %+v", name, family, got)
			}
		}
	}
	got, err := LookupHostname(context.Background(), HostnameQuery{Name: "negative.local", Families: IPv6, Duration: 150 * time.Millisecond}, SelectIfaces(ifaces), SelectIPTraffic(IPv4))
	if err != nil || len(got) != 1 || len(got[0].NoData) != 1 || len(got[0].Addresses) != 0 {
		t.Fatalf("negative: %+v, %v", got, err)
	}
	_, err = LookupHostname(context.Background(), HostnameQuery{Name: "absent.local", Duration: 30 * time.Millisecond}, SelectIfaces(ifaces), SelectIPTraffic(IPv4))
	if !errors.Is(err, ErrNoHostnameResponse) {
		t.Fatalf("silence: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = LookupHostname(ctx, HostnameQuery{Name: "absent.local", Duration: time.Second}, SelectIfaces(ifaces), SelectIPTraffic(IPv4))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	partialCtx, partialCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer partialCancel()
	partial, err := LookupHostname(partialCtx, HostnameQuery{Name: "single.local", Duration: time.Second}, SelectIfaces(ifaces), SelectIPTraffic(IPv4))
	if !errors.Is(err, context.DeadlineExceeded) || len(partial) != 1 || len(partial[0].Addresses) != 2 {
		t.Fatalf("deadline lost partial result: %+v, %v", partial, err)
	}
	var workers sync.WaitGroup
	for n := 0; n < 4; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			got, err := LookupHostname(context.Background(), HostnameQuery{Name: "single.local", Duration: 150 * time.Millisecond}, SelectIfaces(ifaces), SelectIPTraffic(IPv4))
			if err != nil || len(got) != 1 || len(got[0].Addresses) != 2 {
				t.Errorf("concurrent: %+v, %v", got, err)
			}
		}()
	}
	workers.Wait()
}

func TestHostnameTransportErrorsAndCleanup(t *testing.T) {
	ifaces := testMulticastIfaces(t)
	conf := applyOpts(SelectIfaces(ifaces), SelectIPTraffic(IPv4))
	conf.hostname = true
	for _, mode := range []string{"cancel", "read-failure", "write-failure", "silence"} {
		t.Run(mode, func(t *testing.T) {
			c, err := newClient(conf)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			q, _ := normalizeHostnameQuery(HostnameQuery{Name: "cleanup.local", Duration: 60 * time.Millisecond})
			if mode == "write-failure" {
				c.ipv4conn.Close()
			}
			if mode == "cancel" || mode == "read-failure" {
				done := make(chan struct{})
				go func() {
					defer close(done)
					time.Sleep(10 * time.Millisecond)
					if mode == "cancel" {
						cancel()
					} else {
						c.ipv4conn.Close()
					}
				}()
				defer func() { <-done }()
			}
			_, err = c.lookupHostname(ctx, q)
			switch mode {
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel: %v", err)
				}
			case "silence":
				if !errors.Is(err, ErrNoHostnameResponse) {
					t.Fatalf("silence: %v", err)
				}
			default:
				if err == nil || errors.Is(err, ErrNoHostnameResponse) {
					t.Fatalf("transport failure lost: %v", err)
				}
			}
			if _, err := c.ipv4conn.WriteTo([]byte{0}, &ipv4.ControlMessage{IfIndex: ifaces[0].Index}, ipv4Addr); err == nil {
				t.Fatal("socket still open after return")
			}
		})
	}
}

func TestHostnameRetriesUseClientSchedule(t *testing.T) {
	previous := initialQueryInterval
	initialQueryInterval = time.Millisecond
	defer func() { initialQueryInterval = previous }()
	expected := errors.New("controlled second query failure")
	calls := 0
	err := periodicQuery(context.Background(), func() error {
		calls++
		if calls == 2 {
			return expected
		}
		return nil
	}, nil, false)
	if !errors.Is(err, expected) || calls != 2 {
		t.Fatalf("retry: %d, %v", calls, err)
	}
}

func TestHostnameLateAndWrongPortAnswers(t *testing.T) {
	ifaces := testMulticastIfaces(t)
	wrongPort, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongPort.Close()
	packets := ipv4.NewPacketConn(wrongPort)
	if err := packets.SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	if err := packets.SetMulticastTTL(255); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	startHostnameResponder(t, ifaces, func(query *dns.Msg) *dns.Msg {
		if len(query.Question) == 0 || query.Question[0].Name != "late.local." {
			return nil
		}
		response := hostnameMessage(t, "late.local. 120 IN A 192.0.2.10")
		wire, err := response.Pack()
		if err == nil {
			_, err = packets.WriteTo(wire, &ipv4.ControlMessage{IfIndex: ifaces[0].Index}, ipv4Addr)
		}
		sent <- err
		// The valid-source reply arrives only after the collection window closed.
		time.Sleep(150 * time.Millisecond)
		return response
	})
	got, err := LookupHostname(context.Background(), HostnameQuery{Name: "late.local", Families: IPv4, Duration: 50 * time.Millisecond}, SelectIfaces(ifaces), SelectIPTraffic(IPv4))
	if !errors.Is(err, ErrNoHostnameResponse) || len(got) != 0 {
		t.Fatalf("wrong-port or late answer accepted: %+v, %v", got, err)
	}
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("controlled responder did not receive the query")
	}
}

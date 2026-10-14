package zeroconf

import (
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func testProxyServer(v4, v6 []string) *Server {
	entry := newServiceEntry("API", "_https._tcp", "local")
	entry.HostName = "api.example.local."
	for _, address := range v4 {
		entry.AddrIPv4 = append(entry.AddrIPv4, net.ParseIP(address))
	}
	for _, address := range v6 {
		entry.AddrIPv6 = append(entry.AddrIPv6, net.ParseIP(address))
	}
	return &Server{service: entry, ttl: defaultServiceTTL, hostTTL: defaultHostTTL, probes: map[int]*interfaceProbe{1: {established: true}}}
}

func ttlTestServiceServer(opts ...ServerOption) *Server {
	entry := newServiceEntry("TTL test", "_ttl-test._tcp", "local")
	entry.HostName = "ttl-test.local."
	entry.Port = 8080
	entry.Text = []string{"id=ttl-test"}
	entry.AddrIPv4 = []net.IP{net.ParseIP("192.0.2.10")}
	entry.AddrIPv6 = []net.IP{net.ParseIP("2001:db8::10")}
	conf := applyServerOpts(opts...)
	return &Server{service: entry, ttl: conf.ttl, hostTTL: conf.hostTTL, probes: map[int]*interfaceProbe{1: {established: true}}}
}

func ttlTestHostnameServer(opts ...ServerOption) *Server {
	host, _ := newHostnameRegistration("ttl-test.local.", []string{"192.0.2.10", "2001:db8::10"})
	conf := applyServerOpts(opts...)
	return &Server{hostname: host, ttl: conf.ttl, hostTTL: conf.hostTTL, probes: map[int]*interfaceProbe{1: {established: true}}}
}

func assertRecordTTLs(t *testing.T, msg *dns.Msg, want map[uint16]uint32) {
	t.Helper()
	seen := make(map[uint16]bool)
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), msg.Extra...) {
		ttl, ok := want[rr.Header().Rrtype]
		if !ok {
			t.Fatalf("unexpected record type %d: %s", rr.Header().Rrtype, rr)
		}
		if rr.Header().Ttl != ttl {
			t.Errorf("%s TTL = %d, want %d", rr, rr.Header().Ttl, ttl)
		}
		seen[rr.Header().Rrtype] = true
	}
	for rrtype := range want {
		if !seen[rrtype] {
			t.Errorf("record type %d missing", rrtype)
		}
	}
}

func TestRegistrationTTLDefaults(t *testing.T) {
	service := ttlTestServiceServer()
	var lookup dns.Msg
	service.composeLookupAnswers(&lookup, service.ttl, 1, true)
	assertRecordTTLs(t, &lookup, map[uint16]uint32{
		dns.TypeA: defaultHostTTL, dns.TypeAAAA: defaultHostTTL,
		dns.TypePTR: defaultServiceTTL, dns.TypeSRV: defaultServiceTTL, dns.TypeTXT: defaultServiceTTL,
	})

	var serviceEnumeration dns.Msg
	service.serviceTypeName(&serviceEnumeration, service.ttl)
	assertRecordTTLs(t, &serviceEnumeration, map[uint16]uint32{dns.TypePTR: defaultServiceTTL})
	var browse dns.Msg
	service.composeBrowsingAnswers(&browse, 1)
	assertRecordTTLs(t, &browse, map[uint16]uint32{
		dns.TypeA: defaultHostTTL, dns.TypeAAAA: defaultHostTTL,
		dns.TypePTR: defaultServiceTTL, dns.TypeSRV: defaultServiceTTL, dns.TypeTXT: defaultServiceTTL,
	})

	hostname := ttlTestHostnameServer()
	var hostResponse dns.Msg
	hostname.composeLookupAnswers(&hostResponse, hostname.ttl, 1, true)
	assertRecordTTLs(t, &hostResponse, map[uint16]uint32{dns.TypeA: defaultHostTTL, dns.TypeAAAA: defaultHostTTL})
}

func TestRegistrationTTLOptionOverridesServiceAndHostRecords(t *testing.T) {
	const ttl = 30
	wantService := map[uint16]uint32{
		dns.TypeA: ttl, dns.TypeAAAA: ttl, dns.TypePTR: ttl, dns.TypeSRV: ttl, dns.TypeTXT: ttl,
	}
	service := ttlTestServiceServer(TTL(ttl))
	var lookup dns.Msg
	service.composeLookupAnswers(&lookup, service.ttl, 1, true)
	assertRecordTTLs(t, &lookup, wantService)
	var browse dns.Msg
	service.composeBrowsingAnswers(&browse, 1)
	assertRecordTTLs(t, &browse, wantService)
	var serviceEnumeration dns.Msg
	service.serviceTypeName(&serviceEnumeration, service.ttl)
	assertRecordTTLs(t, &serviceEnumeration, map[uint16]uint32{dns.TypePTR: ttl})

	hostname := ttlTestHostnameServer(TTL(ttl))
	var hostResponse dns.Msg
	hostname.composeLookupAnswers(&hostResponse, hostname.ttl, 1, true)
	assertRecordTTLs(t, &hostResponse, map[uint16]uint32{dns.TypeA: ttl, dns.TypeAAAA: ttl})
	assertRecordTTLs(t, directHostnameResponse(t, hostname, dns.TypeANY), map[uint16]uint32{dns.TypeA: ttl, dns.TypeAAAA: ttl})
}

func directHostnameResponse(t *testing.T, server *Server, qtype uint16) *dns.Msg {
	t.Helper()
	var name string
	if server.hostname != nil {
		name = server.hostname.name
	} else {
		name = server.service.HostName
	}
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	response := new(dns.Msg)
	response.SetReply(query)
	if err := server.handleQuestion(query.Question[0], response, query, 1); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestProxyAnswersDirectHostnameAddressQueries(t *testing.T) {
	server := testProxyServer([]string{"192.0.2.10"}, []string{"2001:db8::10"})
	for _, test := range []struct {
		name  string
		qtype uint16
		want  []uint16
	}{
		{name: "A", qtype: dns.TypeA, want: []uint16{dns.TypeA}},
		{name: "AAAA", qtype: dns.TypeAAAA, want: []uint16{dns.TypeAAAA}},
		{name: "ANY", qtype: dns.TypeANY, want: []uint16{dns.TypeA, dns.TypeAAAA}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := directHostnameResponse(t, server, test.qtype)
			got := make([]uint16, 0, len(response.Answer))
			for _, record := range response.Answer {
				got = append(got, record.Header().Rrtype)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("answer types = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestProxyAnswersIPv4OnlyAAAAWithNegativeNSEC(t *testing.T) {
	server := testProxyServer([]string{"192.0.2.10"}, nil)
	response := directHostnameResponse(t, server, dns.TypeAAAA)
	if len(response.Answer) != 1 {
		t.Fatalf("answer count = %d, want one NSEC", len(response.Answer))
	}
	negative, ok := response.Answer[0].(*dns.NSEC)
	if !ok {
		t.Fatalf("answer = %T, want NSEC", response.Answer[0])
	}
	if negative.Hdr.Name != server.service.HostName || negative.NextDomain != server.service.HostName {
		t.Fatalf("NSEC names = %q, %q, want %q", negative.Hdr.Name, negative.NextDomain, server.service.HostName)
	}
	if !reflect.DeepEqual(negative.TypeBitMap, []uint16{dns.TypeA}) {
		t.Fatalf("NSEC types = %#v, want A", negative.TypeBitMap)
	}
	if negative.Hdr.Ttl != 120 {
		t.Fatalf("NSEC TTL = %d, want 120", negative.Hdr.Ttl)
	}
}

func TestProxyIncludesNegativeNSECWithServiceAdditionalRecords(t *testing.T) {
	server := testProxyServer([]string{"192.0.2.10"}, nil)
	response := new(dns.Msg)
	query := new(dns.Msg)
	query.SetQuestion(server.service.ServiceName(), dns.TypePTR)
	response.SetReply(query)
	if err := server.handleQuestion(query.Question[0], response, query, 1); err != nil {
		t.Fatal(err)
	}
	var negative *dns.NSEC
	for _, record := range response.Extra {
		if candidate, ok := record.(*dns.NSEC); ok {
			negative = candidate
		}
	}
	if negative == nil {
		t.Fatalf("additional records = %#v, want NSEC", response.Extra)
	}
	if !reflect.DeepEqual(negative.TypeBitMap, []uint16{dns.TypeA}) {
		t.Fatalf("additional NSEC types = %#v, want A", negative.TypeBitMap)
	}
}

package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ErrNoHostnameResponse means no live requested address or NSEC negative answer
// was collected. Silence is not an authoritative assertion that a name is absent.
var ErrNoHostnameResponse = errors.New("no mDNS hostname response")

// HostnameQuery describes a one-shot multicast lookup. Name must be a DNS
// hostname below .local, with an optional trailing dot. Families selects address
// records independently of SelectIPTraffic. Zero means both address families.
// Duration is the full collection window, starting after transport setup. Zero
// means one second. Longer windows reuse the service resolver's retry schedule.
type HostnameQuery struct {
	Name     string
	Families IPType
	Duration time.Duration
}

// HostnameAddress retains an address record's received TTL and effective expiry.
// Expiry can be shortened by goodbye or cache-flush processing. The caller owns IP.
type HostnameAddress struct {
	IP     net.IP
	TTL    uint32
	Expiry time.Time
}

// HostnameNoData is an explicit NSEC assertion for one address family on one
// link. An unanswered family has no such entry and remains unknown.
type HostnameNoData struct {
	Family IPType
	TTL    uint32
	Expiry time.Time
}

// HostnameResult contains one link's independent answer. InterfaceIndex is the
// canonical net.Interface index. Resolve it to the platform's IPv6 zone before
// using a link-local address; Windows IPv4 and IPv6 adapter indices can differ.
// Same-named hosts on different links are never combined. Results are snapshots,
// not subscriptions; they have no validity guarantee beyond their record expiry.
type HostnameResult struct {
	Name           string
	InterfaceIndex int
	Addresses      []HostnameAddress
	NoData         []HostnameNoData
}

// LookupHostname sends direct A/AAAA questions without DNS-SD service records.
// It collects for the entire query duration and then closes all sockets and waits
// for its workers. Nil error means at least one live address or explicit negative
// answer, not that every family or every link answered. Silence on other links
// and missing families remain unknown. Cancellation, context deadline and I/O
// failure return their error together with any live partial results. Calls are
// independent and may run concurrently. UnicastDNS and Unannouncements are not
// supported; no system resolver or public DNS fallback is used.
func LookupHostname(ctx context.Context, query HostnameQuery, opts ...ClientOption) ([]HostnameResult, error) {
	query, err := normalizeHostnameQuery(query)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conf := applyOpts(opts...)
	if conf.unicast || len(conf.resolvers) != 0 || conf.unannouncements {
		return nil, fmt.Errorf("hostname lookup supports multicast one-shot options only")
	}
	if conf.listenOn == 0 || conf.listenOn & ^IPType(IPv4AndIPv6) != 0 {
		return nil, fmt.Errorf("invalid mDNS traffic selection %d", conf.listenOn)
	}
	conf.hostname = true
	c, err := newClient(conf)
	if err != nil {
		return nil, err
	}
	return c.lookupHostname(ctx, query)
}

func normalizeHostnameQuery(q HostnameQuery) (HostnameQuery, error) {
	q.Name = dns.CanonicalName(q.Name)
	labels := strings.Split(strings.TrimSuffix(q.Name, "."), ".")
	if _, ok := dns.IsDomainName(q.Name); !ok || len(labels) < 2 || labels[len(labels)-1] != "local" {
		return q, fmt.Errorf("hostname must be below .local")
	}
	for _, label := range labels {
		if len(label) == 0 || label[0] == '-' || label[len(label)-1] == '-' {
			return q, fmt.Errorf("invalid hostname label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return q, fmt.Errorf("invalid hostname label %q", label)
			}
		}
	}
	if q.Families == 0 {
		q.Families = IPv4AndIPv6
	}
	if q.Families & ^IPType(IPv4AndIPv6) != 0 {
		return q, fmt.Errorf("invalid hostname address families %d", q.Families)
	}
	if q.Duration < 0 {
		return q, fmt.Errorf("negative hostname collection duration")
	}
	if q.Duration == 0 {
		q.Duration = time.Second
	}
	return q, nil
}

func hostnameQuestion(q HostnameQuery) *dns.Msg {
	m := new(dns.Msg)
	for _, family := range []IPType{IPv4, IPv6} {
		if q.Families&family != 0 {
			m.Question = append(m.Question, dns.Question{Name: q.Name, Qtype: hostnameRRType(family), Qclass: dns.ClassINET})
		}
	}
	return m
}

func hostnameRRType(family IPType) uint16 {
	if family == IPv4 {
		return dns.TypeA
	}
	return dns.TypeAAAA
}

func (c *client) lookupHostname(ctx context.Context, q HostnameQuery) ([]HostnameResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); c.shutdown(); workers.Wait() }()
	type packet struct {
		msg    *dns.Msg
		index  int
		source net.Addr
	}
	packets := make(chan packet, 32)
	failures := make(chan error, 3)
	startReader := func(conn interface{}) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := c.receive(ctx, conn, func(msg *dns.Msg, index int, source net.Addr) bool {
				select {
				case packets <- packet{msg, index, source}:
					return true
				case <-ctx.Done():
					return false
				}
			})
			if err != nil {
				select {
				case failures <- err:
				case <-ctx.Done():
				}
			}
		}()
	}
	if c.ipv4conn != nil {
		startReader(c.ipv4conn)
	}
	if c.ipv6conn != nil {
		startReader(c.ipv6conn)
	}
	deadline := time.Now().Add(q.Duration)
	timer := time.NewTimer(q.Duration)
	defer timer.Stop()
	workers.Add(1)
	go func() {
		defer workers.Done()
		err := periodicQuery(ctx, func() error { return c.sendQuery(hostnameQuestion(q)) }, nil, false)
		if err != nil {
			select {
			case failures <- err:
			case <-ctx.Done():
			}
		}
	}()
	answers := newHostnameAnswers(q, c.ifaces)
	finish := func(err error) ([]HostnameResult, error) {
		if err == nil {
			select {
			case err = <-failures:
			default:
			}
		}
		results := answers.snapshot(time.Now())
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil && len(results) == 0 {
			err = ErrNoHostnameResponse
		}
		return results, err
	}
	for {
		select {
		case <-ctx.Done():
			return finish(ctx.Err())
		case err := <-failures:
			return finish(err)
		case <-timer.C:
			return finish(nil)
		case p := <-packets:
			now := time.Now()
			if !now.Before(deadline) {
				return finish(nil)
			}
			source, ok := p.source.(*net.UDPAddr)
			if !ok || source.Port != ipv4Addr.Port {
				continue
			}
			answers.accept(p.msg, p.index, now)
		}
	}
}

type hostnameRecordKey struct {
	index   int
	family  IPType
	address string
}
type hostnameRecord struct {
	ip               net.IP
	ttl              uint32
	expiry, received time.Time
}
type hostnameAnswers struct {
	query   HostnameQuery
	ifaces  []net.Interface
	records map[hostnameRecordKey]hostnameRecord
}

func newHostnameAnswers(query HostnameQuery, ifaces []net.Interface) *hostnameAnswers {
	return &hostnameAnswers{query: query, ifaces: ifaces, records: make(map[hostnameRecordKey]hostnameRecord)}
}

func (a *hostnameAnswers) accept(msg *dns.Msg, index int, now time.Time) {
	if !hasInterface(a.ifaces, index) || index <= 0 || !msg.Response || !msg.Authoritative || msg.Opcode != dns.OpcodeQuery || msg.Rcode != dns.RcodeSuccess {
		return
	}
	// Authority records in queries are proposals, never established answers.
	sections := append(append([]dns.RR(nil), msg.Answer...), msg.Extra...)
	updates := make(map[hostnameRecordKey]hostnameRecord)
	flush := make(map[IPType]bool)
	for _, rr := range sections {
		h := rr.Header()
		if h.Class & ^uint16(qClassCacheFlush) != dns.ClassINET || dns.CanonicalName(h.Name) != a.query.Name {
			continue
		}
		var family IPType
		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			family, ip = IPv4, rr.A.To4()
		case *dns.AAAA:
			family = IPv6
			if rr.AAAA.To4() == nil {
				ip = rr.AAAA.To16()
			}
		default:
			continue
		}
		if family&a.query.Families == 0 || ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		key := hostnameRecordKey{index, family, ip.String()}
		updates[key] = hostnameRecord{append(net.IP(nil), ip...), h.Ttl, now.Add(time.Duration(h.Ttl) * time.Second), now}
		if h.Ttl > 0 && h.Class&qClassCacheFlush != 0 {
			flush[family] = true
		}
	}
	for key, record := range a.records {
		if !record.expiry.After(now) {
			delete(a.records, key)
			continue
		}
		if key.index == index && flush[key.family] && record.received.Before(now.Add(-time.Second)) {
			if _, renewed := updates[key]; !renewed {
				a.shorten(key, record, now)
			}
		}
	}
	for key, record := range updates {
		if record.ttl == 0 {
			if previous, ok := a.records[key]; ok {
				a.shorten(key, previous, now)
			}
			continue
		}
		a.records[key] = record
		delete(a.records, hostnameRecordKey{index, key.family, ""})
	}
	for _, rr := range sections {
		nsec, ok := rr.(*dns.NSEC)
		if !ok || dns.CanonicalName(nsec.Hdr.Name) != a.query.Name || nsec.Hdr.Class & ^uint16(qClassCacheFlush) != dns.ClassINET {
			continue
		}
		// NextDomain is intentionally ignored per RFC 6762 section 6.1.
		present := make(map[uint16]bool)
		for _, typ := range nsec.TypeBitMap {
			present[typ] = true
		}
		if present[dns.TypeNSEC] {
			continue
		}
		for _, family := range []IPType{IPv4, IPv6} {
			if family&a.query.Families == 0 {
				continue
			}
			key := hostnameRecordKey{index, family, ""}
			if present[hostnameRRType(family)] {
				delete(a.records, key)
				continue
			}
			if nsec.Hdr.Ttl == 0 {
				if record, ok := a.records[key]; ok {
					a.shorten(key, record, now)
				}
				continue
			}
			// A positive answer in this packet wins over a contradictory bitmap.
			positive := false
			for k, record := range updates {
				if k.family == family && record.ttl > 0 {
					positive = true
				}
			}
			if positive {
				continue
			}
			for k, record := range a.records {
				if k.index == index && k.family == family && k.address != "" {
					a.shorten(k, record, now)
				}
			}
			a.records[key] = hostnameRecord{ttl: nsec.Hdr.Ttl, expiry: now.Add(time.Duration(nsec.Hdr.Ttl) * time.Second), received: now}
		}
	}
}

func (a *hostnameAnswers) shorten(key hostnameRecordKey, record hostnameRecord, now time.Time) {
	if expiry := now.Add(time.Second); record.expiry.After(expiry) {
		record.expiry = expiry
		a.records[key] = record
	}
}

func (a *hostnameAnswers) snapshot(now time.Time) []HostnameResult {
	links := make(map[int]*HostnameResult)
	for key, record := range a.records {
		if !record.expiry.After(now) {
			continue
		}
		link := links[key.index]
		if link == nil {
			link = &HostnameResult{Name: a.query.Name, InterfaceIndex: key.index}
			links[key.index] = link
		}
		if key.address == "" {
			link.NoData = append(link.NoData, HostnameNoData{key.family, record.ttl, record.expiry})
		} else {
			link.Addresses = append(link.Addresses, HostnameAddress{append(net.IP(nil), record.ip...), record.ttl, record.expiry})
		}
	}
	var results []HostnameResult
	for _, link := range links {
		// A still-live positive record takes precedence during a negative grace period.
		noData := link.NoData[:0]
		for _, negative := range link.NoData {
			positive := false
			for _, addr := range link.Addresses {
				if (addr.IP.To4() != nil) == (negative.Family == IPv4) {
					positive = true
				}
			}
			if !positive {
				noData = append(noData, negative)
			}
		}
		link.NoData = noData
		sort.Slice(link.Addresses, func(i, j int) bool { return link.Addresses[i].IP.String() < link.Addresses[j].IP.String() })
		sort.Slice(link.NoData, func(i, j int) bool { return link.NoData[i].Family < link.NoData[j].Family })
		results = append(results, *link)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].InterfaceIndex < results[j].InterfaceIndex })
	return results
}

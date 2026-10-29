package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type hostnameFamilyAnswer struct {
	addresses []HostnameAddress
	negative  *HostnameNoData
	err       error
}

func lookupUnicastHostname(ctx context.Context, q HostnameQuery, opts clientOpts) ([]HostnameResult, error) {
	ctx, cancel := context.WithTimeout(ctx, q.Duration)
	defer cancel()
	servers, err := unicastResolvers(ctx, opts)
	if err != nil {
		return nil, err
	}
	answers := make(chan hostnameFamilyAnswer, 2)
	var workers sync.WaitGroup
	count := 0
	for _, family := range []IPType{IPv4, IPv6} {
		if q.Families&family == 0 {
			continue
		}
		count++
		workers.Add(1)
		go func(family IPType) {
			defer workers.Done()
			answers <- lookupDNSHostnameFamily(ctx, q.Name, family, servers, q.Transport == HostnameUnicast || opts.unicast)
		}(family)
	}
	result := HostnameResult{Name: q.Name, Transport: HostnameUnicast}
	var failures []error
	// All exchanges honor ctx. Receive every worker's terminal result before
	// returning, including partial positives when another family times out.
	for i := 0; i < count; i++ {
		answer := <-answers
		result.Addresses = append(result.Addresses, answer.addresses...)
		if answer.negative != nil {
			result.NoData = append(result.NoData, *answer.negative)
		}
		if answer.err != nil {
			failures = append(failures, answer.err)
		}
	}
	workers.Wait()
	sort.Slice(result.Addresses, func(i, j int) bool { return result.Addresses[i].IP.String() < result.Addresses[j].IP.String() })
	sort.Slice(result.NoData, func(i, j int) bool { return result.NoData[i].Family < result.NoData[j].Family })
	var results []HostnameResult
	if len(result.Addresses)+len(result.NoData) != 0 {
		results = []HostnameResult{result}
	}
	if ctx.Err() != nil {
		return results, ctx.Err()
	}
	return results, errors.Join(failures...)
}

func lookupDNSHostnameFamily(ctx context.Context, name string, family IPType, servers func(string) []string, explicitUnicast bool) hostnameFamilyAnswer {
	seen := make(map[string]bool)
	var aliasExpiry time.Time
	for hop := 0; hop < 16; hop++ {
		if err := ctx.Err(); err != nil {
			return hostnameFamilyAnswer{err: err}
		}
		if seen[name] {
			return hostnameFamilyAnswer{err: fmt.Errorf("CNAME loop at %s", name)}
		}
		seen[name] = true
		if !explicitUnicast && dns.IsSubDomain("local.", name) {
			return hostnameFamilyAnswer{err: fmt.Errorf("automatic unicast lookup cannot follow CNAME into .local")}
		}
		question := dns.Question{Name: name, Qtype: hostnameRRType(family), Qclass: dns.ClassINET}
		var failures []error
		follow := ""
		for _, server := range servers(name) {
			message, err := exchangeDNSQuestion(ctx, question, server)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			now := time.Now()
			answer, canonical, expiry, next, err := parseHostnameDNS(message, question, now, explicitUnicast)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if !expiry.IsZero() {
				aliasExpiry = earlier(aliasExpiry, expiry)
			}
			if next {
				follow = canonical
				break
			}
			if answer.negative {
				expiry := answer.expiry
				if !aliasExpiry.IsZero() {
					expiry = earlier(expiry, aliasExpiry)
				}
				return hostnameFamilyAnswer{negative: &HostnameNoData{Family: family, TTL: uint32(answer.expiry.Sub(answer.observed) / time.Second), Expiry: expiry, NXDOMAIN: message.Rcode == dns.RcodeNameError}}
			}
			result := hostnameFamilyAnswer{}
			for _, record := range answer.records {
				var ip net.IP
				switch record := record.(type) {
				case *dns.A:
					ip = record.A.To4()
				case *dns.AAAA:
					if record.AAAA.To4() == nil {
						ip = record.AAAA.To16()
					}
				}
				if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
					continue
				}
				h := record.Header()
				expiry := now.Add(time.Duration(h.Ttl) * time.Second)
				if !aliasExpiry.IsZero() {
					expiry = earlier(expiry, aliasExpiry)
				}
				duplicate := false
				for i, previous := range result.addresses {
					if previous.IP.Equal(ip) {
						if expiry.Before(previous.Expiry) {
							result.addresses[i].Expiry = expiry
							result.addresses[i].TTL = h.Ttl
						}
						duplicate = true
						break
					}
				}
				if !duplicate {
					result.addresses = append(result.addresses, HostnameAddress{Name: canonical, IP: append(net.IP(nil), ip...), TTL: h.Ttl, Expiry: expiry})
				}
			}
			if len(result.addresses) != 0 {
				return result
			}
			failures = append(failures, fmt.Errorf("no usable address in DNS response for %s", name))
		}
		if follow != "" {
			name = follow
			continue
		}
		if len(failures) == 0 {
			failures = append(failures, fmt.Errorf("no DNS resolver configured for %s", name))
		}
		return hostnameFamilyAnswer{err: errors.Join(failures...)}
	}
	return hostnameFamilyAnswer{err: fmt.Errorf("CNAME chain exceeds 16 DNS queries")}
}

// Resolve CNAMEs in an answer while preserving #45's stricter SRV-target parser.
// The returned boolean requests a new query for an alias not completed here.
func parseHostnameDNS(message *dns.Msg, question dns.Question, now time.Time, explicitUnicast bool) (*dnsAnswer, string, time.Time, bool, error) {
	name := question.Name
	seen := make(map[string]bool)
	var expiry time.Time
	for hop := 0; hop < 16; hop++ {
		if seen[name] {
			return nil, name, expiry, false, fmt.Errorf("CNAME loop at %s", name)
		}
		seen[name] = true
		var alias *dns.CNAME
		for _, record := range message.Answer {
			if record.Header().Class != dns.ClassINET || dns.CanonicalName(record.Header().Name) != name {
				continue
			}
			if value, ok := record.(*dns.CNAME); ok {
				if alias != nil && dns.CanonicalName(alias.Target) != dns.CanonicalName(value.Target) {
					return nil, name, expiry, false, fmt.Errorf("conflicting CNAMEs for %s", name)
				}
				alias = value
				expiry = earlier(expiry, now.Add(time.Duration(value.Hdr.Ttl)*time.Second))
			}
		}
		if alias == nil {
			followed := name != question.Name
			filtered := *message
			filtered.Answer = nil
			for _, record := range message.Answer {
				if _, ok := record.(*dns.CNAME); !ok {
					filtered.Answer = append(filtered.Answer, record)
				}
			}
			question.Name = name
			answer, err := parseDNSAnswer(&filtered, question, now)
			if err != nil && followed && message.Rcode == dns.RcodeSuccess {
				// A CNAME without an address or applicable SOA requires another query.
				haveRecord, haveSOA := false, false
				for _, record := range filtered.Answer {
					h := record.Header()
					if h.Class == dns.ClassINET && h.Rrtype == question.Qtype && dns.CanonicalName(h.Name) == name {
						haveRecord = true
					}
				}
				for _, record := range message.Ns {
					if soa, ok := record.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET && dns.IsSubDomain(soa.Hdr.Name, name) {
						haveSOA = true
					}
				}
				if !haveRecord && !haveSOA {
					return nil, name, expiry, true, nil
				}
			}
			return answer, name, expiry, false, err
		}
		normalized, err := normalizeHostnameQuery(HostnameQuery{Name: alias.Target})
		if err != nil {
			return nil, name, expiry, false, err
		}
		name = normalized.Name
		if !explicitUnicast && dns.IsSubDomain("local.", name) {
			return nil, name, expiry, false, fmt.Errorf("automatic unicast lookup cannot follow CNAME into .local")
		}
	}
	return nil, name, expiry, false, fmt.Errorf("CNAME chain exceeds 16 records")
}

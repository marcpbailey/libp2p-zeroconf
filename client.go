package zeroconf

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IPType specifies the IP traffic the client listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, often contain
// both DNS A and AAAA entries.
type IPType uint8

// Options for IPType.
const (
	IPv4        IPType = 0x01
	IPv6        IPType = 0x02
	IPv4AndIPv6        = IPv4 | IPv6 // default option
)

var initialQueryInterval = 4 * time.Second

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	ipv4conn          *ipv4.PacketConn
	ipv6conn          *ipv6.PacketConn
	ifaces            []net.Interface
	unannouncements   bool
	hostnameTransport *hostnameTransport
}

type clientOpts struct {
	listenOn        IPType
	ifaces          []net.Interface
	unannouncements bool
	unicast         bool
	resolvers       []string
	hostname        bool
}

// ClientOption fills the option struct to configure intefaces, etc.
type ClientOption func(*clientOpts)

// SelectIPTraffic selects the type of IP packets (IPv4, IPv6, or both) this
// instance listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, may contain
// both DNS A and AAAA entries.
func SelectIPTraffic(t IPType) ClientOption {
	return func(o *clientOpts) {
		o.listenOn = t
	}
}

// SelectIfaces selects the interfaces to query for mDNS records
func SelectIfaces(ifaces []net.Interface) ClientOption {
	return func(o *clientOpts) {
		o.ifaces = ifaces
	}
}

// Unannouncements emits an expired entry when a previously emitted service is removed.
func Unannouncements() ClientOption {
	return func(o *clientOpts) {
		o.unannouncements = true
	}
}

// Browse for all services of a given type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Browse(ctx context.Context, service, domain string, entries chan<- *ServiceEntry, opts ...ClientOption) error {
	cl, err := newClient(applyOpts(opts...))
	if err != nil {
		return err
	}
	params := defaultParams(service)
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	params.isBrowsing = true
	return cl.run(ctx, params)
}

// Lookup a specific service by its name and type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Lookup(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry, opts ...ClientOption) error {
	cl, err := newClient(applyOpts(opts...))
	if err != nil {
		return err
	}
	params := defaultParams(service)
	params.Instance = instance
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	return cl.run(ctx, params)
}

func applyOpts(options ...ClientOption) clientOpts {
	// Apply default configuration and load supplied options.
	var conf = clientOpts{
		listenOn: IPv4AndIPv6,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}
	return conf
}

func (c *client) run(ctx context.Context, params *lookupParams) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.mainloop(ctx, params)
	}()

	// If previous probe was ok, it should be fine now. In case of an error later on,
	// the entries' queue is closed.
	err := c.periodicQuery(ctx, params)
	cancel()
	<-done
	return err
}

// defaultParams returns a default set of QueryParams.
func defaultParams(service string) *lookupParams {
	return newLookupParams("", service, "local", false, make(chan *ServiceEntry))
}

// Client structure constructor
func newClient(opts clientOpts) (*client, error) {
	ifaces := opts.ifaces
	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}
	var hostname *hostnameTransport
	ifaces4, ifaces6 := ifaces, ifaces
	if opts.hostname {
		var err error
		ifaces, hostname, err = hostnameInterfaces(opts)
		if err != nil {
			return nil, err
		}
		ifaces4, ifaces6 = hostname.ipv4Ifaces, hostname.nativeIPv6
	}
	// IPv4 interfaces
	var ipv4conn *ipv4.PacketConn
	var err4 error
	if (opts.listenOn & IPv4) > 0 {
		if !opts.hostname || len(ifaces4) != 0 {
			ipv4conn, err4 = joinUdp4Multicast(ifaces4, opts.hostname)
			if err4 == nil && opts.hostname {
				if err4 = preparePacket4(ipv4conn); err4 != nil {
					ipv4conn.Close()
					ipv4conn = nil
				}
			}
		}
	}
	// IPv6 interfaces
	var ipv6conn *ipv6.PacketConn
	var err6 error
	if (opts.listenOn & IPv6) > 0 {
		if !opts.hostname || len(ifaces6) != 0 {
			ipv6conn, err6 = joinUdp6Multicast(ifaces6, opts.hostname)
			if err6 == nil && opts.hostname {
				if err6 = preparePacket6(ipv6conn); err6 != nil {
					ipv6conn.Close()
					ipv6conn = nil
				}
			}
		}
	}
	if ipv4conn == nil && ipv6conn == nil {
		switch {
		case err4 != nil && err6 != nil:
			return nil, fmt.Errorf("no supported mDNS transport (IPv4: %v; IPv6: %v)", err4, err6)
		case err4 != nil:
			return nil, fmt.Errorf("IPv4 mDNS transport: %w", err4)
		case err6 != nil:
			return nil, fmt.Errorf("IPv6 mDNS transport: %w", err6)
		default:
			return nil, fmt.Errorf("no mDNS transport enabled")
		}
	}

	if opts.hostname {
		for _, iface := range ifaces {
			if (ipv4conn == nil || !hasInterface(hostname.ipv4Ifaces, iface.Index)) && (ipv6conn == nil || !hasInterface(hostname.ipv6Ifaces, iface.Index)) {
				if ipv4conn != nil {
					ipv4conn.Close()
				}
				if ipv6conn != nil {
					ipv6conn.Close()
				}
				return nil, fmt.Errorf("no usable mDNS transport on interface %d (IPv4: %v; IPv6: %v)", iface.Index, err4, err6)
			}
		}
	}
	return &client{
		hostnameTransport: hostname,
		ipv4conn:          ipv4conn,
		ipv6conn:          ipv6conn,
		ifaces:            ifaces,
		unannouncements:   opts.unannouncements,
	}, nil
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context, params *lookupParams) {
	// start listening for responses
	msgCh := make(chan *dns.Msg, 32)
	if c.ipv4conn != nil {
		go c.recv(ctx, c.ipv4conn, msgCh)
	}
	if c.ipv6conn != nil {
		go c.recv(ctx, c.ipv6conn, msgCh)
	}
	c.mainloopWithMessages(ctx, params, msgCh, systemExpiryClock{})
}

type expiryTimer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

type expiryClock interface {
	Now() time.Time
	NewTimer(time.Duration) expiryTimer
}

type systemExpiryClock struct{}

func (systemExpiryClock) Now() time.Time { return time.Now() }
func (systemExpiryClock) NewTimer(duration time.Duration) expiryTimer {
	return systemExpiryTimer{timer: time.NewTimer(duration)}
}

type systemExpiryTimer struct{ timer *time.Timer }

func (t systemExpiryTimer) C() <-chan time.Time        { return t.timer.C }
func (t systemExpiryTimer) Stop() bool                 { return t.timer.Stop() }
func (t systemExpiryTimer) Reset(d time.Duration) bool { return t.timer.Reset(d) }

func (c *client) mainloopWithMessages(ctx context.Context, params *lookupParams, msgCh <-chan *dns.Msg, clock expiryClock) {
	sentEntries := make(map[string]*ServiceEntry)
	var timer expiryTimer
	var timerC <-chan time.Time
	defer params.done()
	defer c.shutdown()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	stopTimer := func() {
		if timer == nil || timer.Stop() {
			return
		}
		select {
		case <-timer.C():
		default:
		}
	}
	resetTimer := func() {
		var earliest time.Time
		for _, entry := range sentEntries {
			if earliest.IsZero() || entry.Expiry.Before(earliest) {
				earliest = entry.Expiry
			}
		}
		if earliest.IsZero() {
			stopTimer()
			timerC = nil
			return
		}
		delay := earliest.Sub(clock.Now())
		if delay < 0 {
			delay = 0
		}
		if timer == nil {
			timer = clock.NewTimer(delay)
		} else {
			stopTimer()
			timer.Reset(delay)
		}
		timerC = timer.C()
	}
	send := func(entry *ServiceEntry) bool {
		select {
		case params.Entries <- entry:
			return true
		case <-ctx.Done():
			return false
		}
	}
	expireEntries := func() bool {
		now := clock.Now()
		for key, entry := range sentEntries {
			if entry.Expiry.After(now) {
				continue
			}
			if c.unannouncements {
				removed := cloneServiceEntry(entry)
				removed.Removed = true
				if !send(removed) {
					return false
				}
			}
			delete(sentEntries, key)
		}
		resetTimer()
		return true
	}

	for {
		var entries map[string]*ServiceEntry
		var now time.Time
		select {
		case <-ctx.Done():
			return
		case <-timerC:
			if !expireEntries() {
				return
			}
			continue
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			// Probe authority and query known answers are not established answers.
			if !msg.Response {
				continue
			}
			now = clock.Now()
			entries = make(map[string]*ServiceEntry)
			sections := append(msg.Answer, msg.Ns...)
			sections = append(sections, msg.Extra...)

			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.PTR:
					if params.ServiceName() != rr.Hdr.Name {
						continue
					}
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Ptr {
						continue
					}
					if _, ok := entries[rr.Ptr]; !ok {
						entries[rr.Ptr] = newServiceEntry(
							trimDot(strings.Replace(rr.Ptr, rr.Hdr.Name, "", -1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Ptr].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				case *dns.SRV:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = newServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Hdr.Name].HostName = rr.Target
					entries[rr.Hdr.Name].Port = int(rr.Port)
					entries[rr.Hdr.Name].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				case *dns.TXT:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = newServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Hdr.Name].Text = rr.Txt
					entries[rr.Hdr.Name].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				}
			}
			// Associate IPs in a second round as other fields should be filled by now.
			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.A:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv4 = append(entries[k].AddrIPv4, rr.A)
						}
					}
				case *dns.AAAA:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv6 = append(entries[k].AddrIPv6, rr.AAAA)
						}
					}
				}
			}
		}

		if len(entries) > 0 {
			for k, e := range entries {
				if !e.Expiry.After(now) {
					delete(entries, k)
					if sent, ok := sentEntries[k]; ok {
						if c.unannouncements {
							removed := cloneServiceEntry(sent)
							removed.Expiry = e.Expiry
							removed.Removed = true
							if !send(removed) {
								return
							}
						}
						delete(sentEntries, k)
					}
					continue
				}
				if refreshCachedEntry(sentEntries, k, e) {
					continue
				}

				// If this is an DNS-SD query do not throw PTR away.
				// It is expected to have only PTR for enumeration
				if params.ServiceRecord.ServiceTypeName() != params.ServiceRecord.ServiceName() {
					// Require at least one resolved IP address for ServiceEntry
					// TODO: wait some more time as chances are high both will arrive.
					if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
						continue
					}
				}
				// Submit entry to subscriber and cache it.
				// This is also a point to possibly stop probing actively for a
				// service entry.
				if !send(cloneServiceEntry(e)) {
					return
				}
				sentEntries[k] = cloneServiceEntry(e)
				if !params.isBrowsing {
					params.disableProbing()
				}
			}
			resetTimer()
		}
	}
}

func refreshCachedEntry(sentEntries map[string]*ServiceEntry, key string, entry *ServiceEntry) bool {
	cached, ok := sentEntries[key]
	if !ok {
		return false
	}
	if !sameService(cached, entry) {
		return false
	}
	cached.Expiry = entry.Expiry
	return true
}

// Shutdown client will close currently open connections and channel implicitly.
func (c *client) shutdown() {
	if c.ipv4conn != nil {
		c.ipv4conn.Close()
	}
	if c.ipv6conn != nil {
		c.ipv6conn.Close()
	}
}

// Data receiving routine reads from connection, unpacks packets into dns.Msg
// structures and sends them to a given msgCh channel
func (c *client) recv(ctx context.Context, l interface{}, msgCh chan *dns.Msg) {
	_ = c.receive(ctx, l, func(msg *dns.Msg, _ int, _ net.Addr) bool {
		select {
		case msgCh <- msg:
			return true
		case <-ctx.Done():
			return false
		}
	})
}

// receive shares decoding with service discovery, retaining metadata when requested.
func (c *client) receive(ctx context.Context, l interface{}, deliver func(*dns.Msg, int, net.Addr) bool) error {
	var readFrom func([]byte) (n int, index int, src net.Addr, err error)

	switch pConn := l.(type) {
	case *ipv6.PacketConn:
		readFrom = func(b []byte) (n int, index int, src net.Addr, err error) {
			var cm *ipv6.ControlMessage
			if c.hostnameTransport != nil {
				n, cm, src, err = readMulticast6(pConn, b, c.hostnameTransport.ipv6Indexes)
			} else {
				n, cm, src, err = pConn.ReadFrom(b)
			}
			if cm != nil {
				index = cm.IfIndex
			}
			return
		}
	case *ipv4.PacketConn:
		readFrom = func(b []byte) (n int, index int, src net.Addr, err error) {
			var cm *ipv4.ControlMessage
			if c.hostnameTransport != nil {
				n, cm, src, err = readMulticast4(pConn, b)
			} else {
				n, cm, src, err = pConn.ReadFrom(b)
			}
			if cm != nil {
				index = cm.IfIndex
			}
			return
		}

	default:
		return fmt.Errorf("unsupported mDNS packet connection %T", l)
	}
	buf := make([]byte, 65536)
	for ctx.Err() == nil {
		n, index, source, err := readFrom(buf)
		if err != nil {
			return err
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !deliver(msg, index, source) {
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// periodicQuery sens multiple probes until a valid response is received by
// the main processing loop or some timeout/cancel fires.
// TODO: move error reporting to shutdown function as periodicQuery is called from
// go routine context.
func (c *client) periodicQuery(ctx context.Context, params *lookupParams) error {
	return periodicQuery(ctx, func() error { return c.query(params) }, params.stopProbing, params.isBrowsing)
}

func periodicQuery(ctx context.Context, query func() error, stop <-chan struct{}, browsing bool) error {
	// Do the first query immediately.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := query(); err != nil {
		return err
	}

	const maxInterval = 60 * time.Second
	interval := initialQueryInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			// Wait for next iteration.
		case <-stop:
			// Chan is closed (or happened in the past).
			// Done here. Received a matching mDNS entry.
			return nil
		case <-ctx.Done():
			if browsing {
				return nil
			}
			return ctx.Err()
		}

		if err := query(); err != nil {
			return err
		}
		// Exponential increase of the interval with jitter:
		// the new interval will be between 1.5x and 2.5x the old interval, capped at maxInterval.
		if interval != maxInterval {
			interval += time.Duration(rand.Int63n(interval.Nanoseconds())) + interval/2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
		timer.Reset(interval)
	}
}

// Performs the actual query by service name (browse) or service instance name (lookup),
// start response listeners goroutines and loops over the entries channel.
func (c *client) query(params *lookupParams) error {
	var serviceName, serviceInstanceName string
	serviceName = fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// send the query
	m := new(dns.Msg)
	if params.Instance != "" { // service instance name lookup
		serviceInstanceName = fmt.Sprintf("%s.%s", params.Instance, serviceName)
		m.Question = []dns.Question{
			{Name: serviceInstanceName, Qtype: dns.TypeSRV, Qclass: dns.ClassINET},
			{Name: serviceInstanceName, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		}
	} else if len(params.Subtypes) > 0 { // service subtype browse
		m.SetQuestion(params.Subtypes[0], dns.TypePTR)
	} else { // service name browse
		m.SetQuestion(serviceName, dns.TypePTR)
	}
	m.RecursionDesired = false
	return c.sendQuery(m)
}

// Pack the dns.Msg and write to available connections (multicast)
func (c *client) sendQuery(msg *dns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	if c.hostnameTransport != nil {
		return c.sendHostnamePacket(buf)
	}
	if c.ipv4conn != nil {
		// See https://pkg.go.dev/golang.org/x/net/ipv4#pkg-note-BUG
		// As of Golang 1.18.4
		// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
		var wcm ipv4.ControlMessage
		for ifi := range c.ifaces {
			switch runtime.GOOS {
			case "darwin", "ios", "linux":
				wcm.IfIndex = c.ifaces[ifi].Index
			default:
				if err := c.ipv4conn.SetMulticastInterface(&c.ifaces[ifi]); err != nil {
					log.Printf("[WARN] mdns: Failed to set multicast interface: %v", err)
				}
			}
			c.ipv4conn.WriteTo(buf, &wcm, ipv4Addr)
		}
	}
	if c.ipv6conn != nil {
		// See https://pkg.go.dev/golang.org/x/net/ipv6#pkg-note-BUG
		// As of Golang 1.18.4
		// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
		var wcm ipv6.ControlMessage
		for ifi := range c.ifaces {
			switch runtime.GOOS {
			case "darwin", "ios", "linux":
				wcm.IfIndex = c.ifaces[ifi].Index
			default:
				if err := c.ipv6conn.SetMulticastInterface(&c.ifaces[ifi]); err != nil {
					log.Printf("[WARN] mdns: Failed to set multicast interface: %v", err)
				}
			}
			c.ipv6conn.WriteTo(buf, &wcm, ipv6Addr)
		}
	}
	return nil
}

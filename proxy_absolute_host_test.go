package zeroconf

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRegisterProxyPreservesAbsoluteTarget(t *testing.T) {
	for _, test := range []struct {
		name string
		host string
		want string
	}{
		{"absolute-external", "collector.devcloud.urlcast.tv.", "collector.devcloud.urlcast.tv."},
		{"absolute-local", "collector.devcloud.local.", "collector.devcloud.local."},
		{"relative", "collector.devcloud", "collector.devcloud.local."},
		{"qualified-without-dot", "collector.devcloud.local", "collector.devcloud.local"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ifaces := testMulticastIfaces(t)
			instance := fmt.Sprintf("absolute-proxy-%d-%d", os.Getpid(), time.Now().UnixNano())
			server, err := RegisterProxy(instance, "_proxyfqdn._tcp", "local", 9443,
				test.host, []string{"192.0.2.10", "2001:db8::10"}, nil, ifaces)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(server.Shutdown)
			if server.service.HostName != test.want {
				t.Fatalf("SRV target = %q, want %q", server.service.HostName, test.want)
			}
			response := new(dns.Msg)
			server.composeLookupAnswers(response, 30, ifaces[0].Index, true)
			found := map[uint16]bool{}
			for _, record := range append(response.Answer, response.Extra...) {
				switch record := record.(type) {
				case *dns.SRV:
					if record.Target != test.want {
						t.Fatalf("SRV target = %q, want %q", record.Target, test.want)
					}
					found[dns.TypeSRV] = true
				case *dns.A, *dns.AAAA:
					if record.Header().Name != test.want {
						t.Fatalf("address name = %q, want %q", record.Header().Name, test.want)
					}
					found[record.Header().Rrtype] = true
				}
			}
			if !found[dns.TypeSRV] || !found[dns.TypeA] || !found[dns.TypeAAAA] {
				t.Fatalf("missing SRV/A/AAAA records: %v", found)
			}
		})
	}
}

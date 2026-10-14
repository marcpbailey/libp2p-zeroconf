package zeroconf

import (
	"net"
	"testing"
	"time"
)

func TestForkRefreshCachedEntryDoesNotMutateDeliveredEntry(t *testing.T) {
	delivered := &ServiceEntry{Text: []string{"id=one"}, Expiry: time.Now().Add(time.Second)}
	cached := cloneServiceEntry(delivered)
	sent := map[string]*ServiceEntry{"service": cached}
	refreshed := cloneServiceEntry(delivered)
	refreshed.Expiry = delivered.Expiry.Add(10 * time.Second)

	if !refreshCachedEntry(sent, "service", refreshed) {
		t.Fatal("unchanged entry was not treated as an expiry refresh")
	}
	if !delivered.Expiry.Equal(cached.Expiry.Add(-10 * time.Second)) {
		t.Fatalf("delivered expiry changed to %s", delivered.Expiry)
	}
	if !cached.Expiry.Equal(refreshed.Expiry) {
		t.Fatalf("cached expiry = %s, want %s", cached.Expiry, refreshed.Expiry)
	}
}

func TestForkCloneServiceEntryCopiesNestedMetadata(t *testing.T) {
	entry := &ServiceEntry{ServiceRecord: ServiceRecord{Subtypes: []string{"_secure"}}, Text: []string{"id=one"}, AddrIPv4: []net.IP{net.ParseIP("192.0.2.10")}, AddrIPv6: []net.IP{net.ParseIP("2001:db8::10")}}
	cloned := cloneServiceEntry(entry)
	entry.Subtypes[0] = "changed"
	entry.Text[0] = "changed"
	entry.AddrIPv4[0][0] = 198
	entry.AddrIPv6[0][0] = 0x30
	if cloned.Subtypes[0] == "changed" || cloned.Text[0] == "changed" || cloned.AddrIPv4[0].String() != "192.0.2.10" || cloned.AddrIPv6[0].String() != "2001:db8::10" {
		t.Fatal("clone aliases source")
	}
	cloned.Text[0] = "clone changed"
	cloned.AddrIPv4[0][0] = 199
	if entry.Text[0] != "changed" || entry.AddrIPv4[0][0] != 198 {
		t.Fatal("source aliases clone")
	}
}

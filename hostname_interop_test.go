//go:build interop

package zeroconf

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Register records through Bonjour's connection API, with no service instance,
// PTR, SRV or TXT record. Deallocating the connection withdraws both records.
const bonjourHostnamePublisher = `
import ctypes as c, select, socket, sys
lib = c.CDLL('/usr/lib/libSystem.B.dylib')
ref = c.c_void_p()
lib.DNSServiceCreateConnection.argtypes = [c.POINTER(c.c_void_p)]
lib.DNSServiceCreateConnection.restype = c.c_int32
lib.DNSServiceRefSockFD.argtypes = [c.c_void_p]
lib.DNSServiceRefSockFD.restype = c.c_int
lib.DNSServiceProcessResult.argtypes = [c.c_void_p]
lib.DNSServiceProcessResult.restype = c.c_int32
lib.DNSServiceRefDeallocate.argtypes = [c.c_void_p]
callback_type = c.CFUNCTYPE(None, c.c_void_p, c.c_void_p, c.c_uint32, c.c_int32, c.c_void_p)
registered = set()
@callback_type
def callback(ref, record, flags, error, context):
    if error:
        print('ERROR', error, flush=True)
    else:
        registered.add(record)
        if len(registered) == 2: print('READY', flush=True)
register = lib.DNSServiceRegisterRecord
register.argtypes = [c.c_void_p, c.POINTER(c.c_void_p), c.c_uint32, c.c_uint32, c.c_char_p, c.c_uint16, c.c_uint16, c.c_uint16, c.c_void_p, c.c_uint32, callback_type, c.c_void_p]
register.restype = c.c_int32
error = lib.DNSServiceCreateConnection(c.byref(ref))
if error: raise RuntimeError(('create connection', error))
try:
    for family, rrtype, address in [(socket.AF_INET, 1, '192.0.2.60'), (socket.AF_INET6, 28, '2001:db8::60')]:
        data = socket.inet_pton(family, address)
        record = c.c_void_p()
        error = register(ref, c.byref(record), 0x20, int(sys.argv[2]), sys.argv[1].encode(), rrtype, 1, len(data), data, 120, callback, None)
        if error: raise RuntimeError(('register record', error))
    fd = lib.DNSServiceRefSockFD(ref)
    while True:
        select.select([fd], [], [])
        error = lib.DNSServiceProcessResult(ref)
        if error: raise RuntimeError(('process result', error))
finally:
    lib.DNSServiceRefDeallocate(ref)
`

func TestNativeHostnameInterop(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("ZEROCONF_INTEROP_INTERFACE") == "" {
		t.Skip("requires explicit macOS Bonjour interface")
	}
	iface, err := net.InterfaceByName(os.Getenv("ZEROCONF_INTEROP_INTERFACE"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("dns-sd", "-V").CombinedOutput(); err != nil {
		t.Fatalf("Bonjour version: %v: %s", err, out)
	} else {
		t.Logf("%s", out)
	}
	name := fmt.Sprintf("lookup-%d-%d.local.", os.Getpid(), time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	publisher := exec.CommandContext(ctx, "python3", "-c", bonjourHostnamePublisher, name, strconv.Itoa(iface.Index))
	output, err := publisher.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	publisher.Stderr = os.Stderr
	if err := publisher.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publisher.Process.Kill(); publisher.Wait() })
	lines := make(chan string, 4)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	select {
	case line := <-lines:
		if line != "READY" {
			t.Fatalf("native registration: %q", line)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Let startup announcements finish, so the lookup must elicit a fresh reply.
	time.Sleep(3 * time.Second)
	got, err := LookupHostname(ctx, HostnameQuery{Name: name, Duration: 1500 * time.Millisecond}, SelectIfaces([]net.Interface{*iface}), SelectIPTraffic(IPv4))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].InterfaceIndex != iface.Index || len(got[0].Addresses) != 2 || got[0].Addresses[0].IP.String() != "192.0.2.60" || got[0].Addresses[1].IP.String() != "2001:db8::60" {
		t.Fatalf("Bonjour hostname-only answer: %+v", got)
	}
	t.Logf("hostname-only lookup received A and AAAA on %s (%d)", iface.Name, iface.Index)
}

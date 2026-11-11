package admin

import (
	"context"
	"net"
	"testing"
)

type fakeResolver map[string][]net.IP

func (f fakeResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	if ips, ok := f[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestDNSRecords(t *testing.T) {
	dir := newNet(t) // fi-1 chat.example.org 203.0.113.10
	if err := SetIPs(dir, "fi-1", []string{"203.0.113.10", "2001:db8::10"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "ip-1", WSSHost: "192.0.2.5"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "de-1", WSSHost: "de.example.org"}); err != nil {
		t.Fatal(err)
	}
	got, err := DNSRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := "; Add these records at the DNS provider of each domain (TTL 300 recommended)\n" +
		"chat.example.org.    300  IN  A     203.0.113.10\n" +
		"chat.example.org.    300  IN  AAAA  2001:db8::10\n" +
		"; de-1: no IPs recorded (node set-ip --label de-1 --ip ...)\n"
	if got != want {
		t.Fatalf("got\n%s", got)
	}
}

func TestCheckDNS(t *testing.T) {
	dir := newNet(t)
	ok := fakeResolver{"chat.example.org": {net.ParseIP("203.0.113.10")}}
	res, err := CheckDNS(context.Background(), dir, "", ok)
	if err != nil || len(res) != 1 || !res[0].OK {
		t.Fatalf("%v %+v", err, res)
	}
	wrong := fakeResolver{"chat.example.org": {net.ParseIP("192.0.2.1")}}
	res, _ = CheckDNS(context.Background(), dir, "", wrong)
	if res[0].OK || res[0].Missing[0] != "203.0.113.10" || res[0].Unexpected[0] != "192.0.2.1" {
		t.Fatalf("%+v", res[0])
	}
	res, _ = CheckDNS(context.Background(), dir, "", fakeResolver{})
	if res[0].OK || res[0].Err == "" {
		t.Fatalf("%+v", res[0])
	}
	if _, err := AddNode(dir, NodeSpec{Label: "ip-1", WSSHost: "192.0.2.5"}); err != nil {
		t.Fatal(err)
	}
	res, _ = CheckDNS(context.Background(), dir, "ip-1", ok)
	if len(res) != 1 || !res[0].Skipped {
		t.Fatalf("%+v", res)
	}
}

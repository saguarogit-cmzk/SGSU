package main

import (
	"net/http"
	"testing"
)

func TestRemoteIP(t *testing.T) {
	cases := []struct {
		name, remoteAddr, realIP, want string
	}{
		{"direct, no proxy", "192.168.10.20:51234", "", "192.168.10.20"},
		{"behind local proxy", "127.0.0.1:41000", "192.168.50.7", "192.168.50.7"},
		{"ipv6 loopback proxy", "[::1]:41000", "192.168.50.7", "192.168.50.7"},
		// A non-loopback peer must never be able to spoof its identity: the
		// header only means something when set by the local nginx.
		{"spoofed header from outside", "203.0.113.9:443", "10.0.0.1", "203.0.113.9"},
		{"garbage header via proxy", "127.0.0.1:41000", "not-an-ip", "127.0.0.1"},
		{"proxy without header", "127.0.0.1:41000", "", "127.0.0.1"},
	}
	for _, c := range cases {
		r := &http.Request{RemoteAddr: c.remoteAddr, Header: http.Header{}}
		if c.realIP != "" {
			r.Header.Set("X-Real-IP", c.realIP)
		}
		if got := remoteIP(r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

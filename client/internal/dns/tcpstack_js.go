//go:build js

package dns

import (
	"net/netip"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"
)

type tcpDNSServer struct{}

func newTCPDNSServer(*dns.ServeMux, tun.Device, netip.Addr, uint16, uint16) *tcpDNSServer {
	return &tcpDNSServer{}
}

func (t *tcpDNSServer) InjectPacket([]byte) {}

func (t *tcpDNSServer) Stop() {}

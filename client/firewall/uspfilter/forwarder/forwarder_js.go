//go:build js

package forwarder

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xnet"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/util/netrelay"
)

const (
	jsTCPPoolSize       = 256
	jsTCPQueueSize      = 8
	jsTCPBufferSize     = 32 << 10
	jsTCPAcceptSleepMin = 100 * time.Microsecond
	jsTCPAcceptSleepMax = 20 * time.Millisecond
)

var (
	errForwarderClosed      = errors.New("userspace forwarder is closed")
	errForwarderUnsupported = errors.New("userspace forwarder only supports IPv4 TCP on js")
)

// PacketCapture captures raw packets for debugging. Implementations must be
// safe for concurrent use and must not block.
type PacketCapture interface {
	Offer(data []byte, outbound bool)
}

type endpointKey struct {
	addr netip.Addr
	port uint16
}

type ruleKey struct {
	src, dst netip.Addr
	srcPort  uint16
	dstPort  uint16
}

// Forwarder is a lneto-backed TCP userspace forwarder for js/wasm builds.
//
// It intentionally replaces only the TCP path for now. The gVisor forwarder
// uses a promiscuous stack that can accept packets for arbitrary routed
// destination IPs; lneto's IPv4 stack accepts packets addressed to its own
// configured IP. To preserve routed TCP behavior, this implementation creates
// one small lneto stack per destination endpoint (dst IP + TCP port).
type Forwarder struct {
	logger     *nblog.Logger
	flowLogger nftypes.FlowLogger
	device     interface {
		CreateOutboundPacket(payload []byte, dstIP net.IP) error
	}
	netstack bool
	ip       netip.Addr
	mtu      uint16

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	services map[endpointKey]*tcpService
	capture  PacketCapture
	closed   bool
	rules    map[ruleKey][]byte
}

type tcpService struct {
	key      endpointKey
	stack    xnet.StackAsync
	listener net.Listener
	cancel   context.CancelFunc
	done     chan struct{}
}

func New(iface common.IFaceMapper, logger *nblog.Logger, flowLogger nftypes.FlowLogger, netstack bool, mtu uint16) (*Forwarder, error) {
	dev := iface.GetWGDevice()
	if dev == nil {
		return nil, errors.New("forwarding not supported")
	}
	if mtu == 0 {
		mtu = 1500
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		logger:     logger,
		flowLogger: flowLogger,
		device:     dev,
		netstack:   netstack,
		ip:         iface.Address().IP,
		mtu:        mtu,
		ctx:        ctx,
		cancel:     cancel,
		services:   make(map[endpointKey]*tcpService),
		rules:      make(map[ruleKey][]byte),
	}
	logger.Debug("lneto js forwarder initialized for TCP")
	return f, nil
}

func (f *Forwarder) SetCapture(pc PacketCapture) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.capture = pc
}

func (f *Forwarder) InjectIncomingPacket(payload []byte) error {
	key, err := tcpEndpointFromIPv4(payload)
	if err != nil {
		return err
	}
	svc, err := f.ensureTCPService(key)
	if err != nil {
		return err
	}
	if pc := f.getCapture(); pc != nil {
		pc.Offer(payload, false)
	}
	if err := svc.stack.IngressIP(payload); err != nil && !errors.Is(err, lneto.ErrPacketDrop) {
		return err
	}
	return nil
}

func (f *Forwarder) Stop() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.cancel()
	services := make([]*tcpService, 0, len(f.services))
	for _, svc := range f.services {
		services = append(services, svc)
	}
	f.services = nil
	f.mu.Unlock()

	for _, svc := range services {
		svc.stop()
	}
}

func (f *Forwarder) RegisterRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, ruleID []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rules == nil {
		return
	}
	key := ruleKey{src: srcIP, dst: dstIP, srcPort: srcPort, dstPort: dstPort}
	if _, ok := f.rules[key]; !ok {
		f.rules[key] = ruleID
	}
}

func (f *Forwarder) DeleteRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, ruleKey{src: srcIP, dst: dstIP, srcPort: srcPort, dstPort: dstPort})
	delete(f.rules, ruleKey{src: dstIP, dst: srcIP, srcPort: dstPort, dstPort: srcPort})
}

func (f *Forwarder) ensureTCPService(key endpointKey) (*tcpService, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, errForwarderClosed
	}
	if svc, ok := f.services[key]; ok {
		f.mu.Unlock()
		return svc, nil
	}
	f.mu.Unlock()

	svc, err := f.newTCPService(key)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		f.mu.Unlock()
		svc.stop()
		f.mu.Lock()
		return nil, errForwarderClosed
	}
	if existing, ok := f.services[key]; ok {
		svc.stop()
		return existing, nil
	}
	f.services[key] = svc
	return svc, nil
}

func (f *Forwarder) newTCPService(key endpointKey) (*tcpService, error) {
	var seed int64
	if err := binary.Read(crand.Reader, binary.LittleEndian, &seed); err != nil {
		return nil, fmt.Errorf("rand seed: %w", err)
	}
	var hw [6]byte
	if _, err := crand.Read(hw[:]); err != nil {
		return nil, fmt.Errorf("rand mac: %w", err)
	}
	hw[0] &^= 0x01
	hw[0] |= 0x02

	ctx, cancel := context.WithCancel(f.ctx)
	svc := &tcpService{
		key:    key,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	if err := svc.stack.Reset(xnet.StackConfig{
		HardwareAddress:   hw,
		StaticAddress4:    key.addr.As4(),
		MTU:               f.mtu,
		Hostname:          "fw0",
		RandSeed:          seed,
		PassivePeers:      0,
		ICMPQueueLimit:    0,
		MaxActiveTCPPorts: 1,
		MaxActiveUDPPorts: 0,
	}); err != nil {
		cancel()
		return nil, fmt.Errorf("reset lneto stack: %w", err)
	}

	sgo := svc.stack.StackGo(jsBackoff, xnet.StackGoConfig{
		ListenerPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           jsTCPPoolSize,
			QueueSize:          jsTCPQueueSize,
			TxBufSize:          jsTCPBufferSize,
			RxBufSize:          jsTCPBufferSize,
			EstablishedTimeout: 30 * time.Second,
			ClosingTimeout:     10 * time.Second,
			NewBackoff:         func() lneto.BackoffStrategy { return jsBackoff },
		},
		TCPDialTimeout: time.Second,
		TCPDialRetries: 30,
	})
	ln, err := sgo.SocketNetip(ctx, "tcp4", 2, 1, netip.AddrPortFrom(key.addr, key.port), netip.AddrPort{})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("listen tcp %s: %w", key.addrPort(), err)
	}
	listener, ok := ln.(net.Listener)
	if !ok {
		cancel()
		return nil, fmt.Errorf("listen tcp %s: unexpected listener type %T", key.addrPort(), ln)
	}
	svc.listener = listener

	go f.runTCPEgress(ctx, svc)
	go f.runTCPAccept(ctx, svc)
	return svc, nil
}

func (f *Forwarder) runTCPEgress(ctx context.Context, svc *tcpService) {
	defer close(svc.done)
	buf := make([]byte, f.mtu)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, _ := svc.stack.EgressIP(buf)
		if n == 0 {
			time.Sleep(jsBackoff(0))
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		dst, ok := destinationIP(packet)
		if !ok {
			continue
		}
		if pc := f.getCapture(); pc != nil {
			pc.Offer(packet, true)
		}
		if err := f.device.CreateOutboundPacket(packet, net.IP(dst.AsSlice())); err != nil && f.logger.Enabled(nblog.LevelTrace) {
			f.logger.Trace2("forwarder: lneto tcp egress error for %s: %v", dst, err)
		}
	}
}

func (f *Forwarder) runTCPAccept(ctx context.Context, svc *tcpService) {
	defer svc.stop()
	for {
		conn, err := svc.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if f.logger.Enabled(nblog.LevelTrace) {
				f.logger.Trace2("forwarder: lneto tcp accept error for %s: %v", svc.key.addrPort(), err)
			}
			return
		}
		go f.proxyTCP(ctx, svc.key, conn)
	}
}

func (f *Forwarder) proxyTCP(ctx context.Context, key endpointKey, inConn net.Conn) {
	remote := addrPortFromNetAddr(inConn.RemoteAddr())
	flowID := uuid.New()
	f.sendTCPEvent(nftypes.TypeStart, flowID, remote, key, 0, 0)
	var success bool
	defer func() {
		if !success {
			f.sendTCPEvent(nftypes.TypeEnd, flowID, remote, key, 0, 0)
		}
	}()

	dialAddr := net.JoinHostPort(f.determineDialAddr(key.addr).String(), strconv.Itoa(int(key.port)))
	outConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		_ = inConn.Close()
		if f.logger.Enabled(nblog.LevelTrace) {
			f.logger.Trace2("forwarder: lneto tcp dial error for %s: %v", dialAddr, err)
		}
		return
	}

	success = true
	rxBytes, txBytes := netrelay.Relay(ctx, inConn, outConn, netrelay.Options{
		Logger: f.logger,
	})
	f.sendTCPEvent(nftypes.TypeEnd, flowID, remote, key, uint64(rxBytes), uint64(txBytes))
	f.DeleteRuleID(remote.addr, key.addr, remote.port, key.port)
}

func (s *tcpService) stop() {
	s.cancel()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	select {
	case <-s.done:
	default:
	}
}

func (f *Forwarder) getCapture() PacketCapture {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.capture
}

func (f *Forwarder) determineDialAddr(addr netip.Addr) netip.Addr {
	if f.netstack && f.ip == addr {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return addr
}

func (f *Forwarder) sendTCPEvent(typ nftypes.Type, flowID uuid.UUID, src endpointKey, dst endpointKey, rxBytes, txBytes uint64) {
	if f.flowLogger == nil {
		return
	}
	fields := nftypes.EventFields{
		FlowID:     flowID,
		Type:       typ,
		Direction:  nftypes.Ingress,
		Protocol:   nftypes.TCP,
		SourceIP:   src.addr,
		DestIP:     dst.addr,
		SourcePort: src.port,
		DestPort:   dst.port,
		RxBytes:    rxBytes,
		TxBytes:    txBytes,
	}
	if typ == nftypes.TypeStart {
		if ruleID, ok := f.getRuleID(src.addr, dst.addr, src.port, dst.port); ok {
			fields.RuleID = ruleID
		}
	}
	f.flowLogger.StoreEvent(fields)
}

func (f *Forwarder) getRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ruleID, ok := f.rules[ruleKey{src: srcIP, dst: dstIP, srcPort: srcPort, dstPort: dstPort}]; ok {
		return ruleID, true
	}
	ruleID, ok := f.rules[ruleKey{src: dstIP, dst: srcIP, srcPort: dstPort, dstPort: srcPort}]
	return ruleID, ok
}

func tcpEndpointFromIPv4(pkt []byte) (endpointKey, error) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return endpointKey{}, errForwarderUnsupported
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return endpointKey{}, errForwarderUnsupported
	}
	if pkt[9] != byte(nftypes.TCP) {
		return endpointKey{}, errForwarderUnsupported
	}
	dst, ok := netip.AddrFromSlice(pkt[16:20])
	if !ok {
		return endpointKey{}, errForwarderUnsupported
	}
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort == 0 {
		return endpointKey{}, errForwarderUnsupported
	}
	return endpointKey{addr: dst, port: dstPort}, nil
}

func destinationIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFromSlice(pkt[16:20])
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFromSlice(pkt[24:40])
	default:
		return netip.Addr{}, false
	}
}

func addrPortFromNetAddr(addr net.Addr) endpointKey {
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return endpointKey{addr: ip.Unmap(), port: uint16(a.Port)}
	default:
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return endpointKey{}
		}
		ip, _ := netip.ParseAddr(host)
		p, _ := strconv.ParseUint(port, 10, 16)
		return endpointKey{addr: ip.Unmap(), port: uint16(p)}
	}
}

func (k endpointKey) addrPort() netip.AddrPort {
	return netip.AddrPortFrom(k.addr, k.port)
}

func jsBackoff(consecutiveBackoffs uint) time.Duration {
	const maxShift = 15
	sleep := jsTCPAcceptSleepMin << min(consecutiveBackoffs, maxShift)
	if sleep > jsTCPAcceptSleepMax {
		sleep = jsTCPAcceptSleepMax
	}
	return sleep
}

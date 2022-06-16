package peerwg

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tabbed/pqtype"
	"golang.org/x/xerrors"
	"inet.af/netaddr"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	tslogger "tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg/nmcfg"

	"cdr.dev/slog"
)

const peerMessageSeparator byte = '\n'

type WireguardPeerMessage struct {
	Recipient uuid.UUID       `json:"recipient"`
	Disco     key.DiscoPublic `json:"disco"`
	Public    key.NodePublic  `json:"public"`
	IPv6      netaddr.IP      `json:"ipv6"`
}

func WireguardPeerMessageRecipientHint(agentID []byte, msg []byte) (bool, error) {
	idx := bytes.Index(msg, []byte{10})
	if idx == -1 {
		return false, xerrors.Errorf("invalid peer message, no separator")
	}

	return bytes.Equal(agentID, msg[:idx]), nil
}

func (pm *WireguardPeerMessage) UnmarshalText(text []byte) error {
	sp := bytes.Split(text, []byte{peerMessageSeparator})
	if len(sp) != 4 {
		return xerrors.Errorf("expected 4 parts, got %d", len(sp))
	}

	err := pm.Recipient.UnmarshalText(sp[0])
	if err != nil {
		return xerrors.Errorf("parse recipient: %w", err)
	}

	err = pm.Disco.UnmarshalText(sp[1])
	if err != nil {
		return xerrors.Errorf("parse disco: %w", err)
	}

	err = pm.Public.UnmarshalText(sp[2])
	if err != nil {
		return xerrors.Errorf("parse public: %w", err)
	}

	pm.IPv6, err = netaddr.ParseIP(string(sp[3]))
	if err != nil {
		return xerrors.Errorf("parse ipv6: %w", err)
	}

	return nil
}

func (pm WireguardPeerMessage) MarshalText() ([]byte, error) {
	const expectedLen = 223
	var buf bytes.Buffer
	buf.Grow(expectedLen)

	recp, _ := pm.Recipient.MarshalText()
	_, _ = buf.Write(recp)
	_ = buf.WriteByte(peerMessageSeparator)

	disco, _ := pm.Disco.MarshalText()
	_, _ = buf.Write(disco)
	_ = buf.WriteByte(peerMessageSeparator)

	pub, _ := pm.Public.MarshalText()
	_, _ = buf.Write(pub)
	_ = buf.WriteByte(peerMessageSeparator)

	ipv6 := pm.IPv6.StringExpanded()
	_, _ = buf.WriteString(ipv6)

	// Ensure we're always allocating exactly enough.
	if buf.Len() != expectedLen {
		panic("buffer length mismatch: want 221, got " + strconv.Itoa(buf.Len()))
	}
	return buf.Bytes(), nil
}

func UUIDToInet(uid uuid.UUID) pqtype.Inet {
	uid[0] = 0xfd
	uid[1] = 0x7a
	uid[2] = 0x11
	uid[3] = 0x5c
	uid[4] = 0xa1
	uid[5] = 0xe0

	return pqtype.Inet{
		Valid: true,
		IPNet: net.IPNet{
			IP:   uid[:],
			Mask: net.CIDRMask(128, 128),
		},
	}
}

func UUIDToNetaddr(uid uuid.UUID) netaddr.IP {
	// fd7a:115c:a1e0
	uid[0] = 0xfd
	uid[1] = 0x7a
	uid[2] = 0x11
	uid[3] = 0x5c
	uid[4] = 0xa1
	uid[5] = 0xe0

	return netaddr.IPFrom16(uid)
}

var derpMap = &tailcfg.DERPMap{
	Regions: map[int]*tailcfg.DERPRegion{
		9: {
			RegionID:   9,
			RegionCode: "dfw",
			RegionName: "Dallas",
			Avoid:      false,
			Nodes: []*tailcfg.DERPNode{
				{
					Name:             "9a",
					RegionID:         9,
					HostName:         "derp9.tailscale.com",
					CertName:         "",
					IPv4:             "207.148.3.137",
					IPv6:             "2001:19f0:6401:1d9c:5400:2ff:feef:bb82",
					STUNPort:         0,
					STUNOnly:         false,
					DERPPort:         0,
					InsecureForTests: false,
					STUNTestIP:       "",
				},
				{
					Name:             "9c",
					RegionID:         9,
					HostName:         "derp9c.tailscale.com",
					CertName:         "",
					IPv4:             "155.138.243.219",
					IPv6:             "2001:19f0:6401:fe7:5400:3ff:fe8d:6d9c",
					STUNPort:         0,
					STUNOnly:         false,
					DERPPort:         0,
					InsecureForTests: false,
					STUNTestIP:       "",
				},
				{
					Name:             "9b",
					RegionID:         9,
					HostName:         "derp9b.tailscale.com",
					CertName:         "",
					IPv4:             "144.202.67.195",
					IPv6:             "2001:19f0:6401:eb5:5400:3ff:fe8d:6d9b",
					STUNPort:         0,
					STUNOnly:         false,
					DERPPort:         0,
					InsecureForTests: false,
					STUNTestIP:       "",
				},
			},
		},
	},
	OmitDefaultRegions: true,
}

var logf tslogger.Logf = log.Printf

type WireguardNetwork struct {
	mu      sync.Mutex
	logger  slog.Logger
	Private key.NodePrivate
	Disco   key.DiscoPublic

	Engine   wgengine.Engine
	Netstack *netstack.Impl
	Magic    *magicsock.Conn

	netMap    *netmap.NetworkMap
	listeners map[listenKey]*listener
}

func NewWireguardNetwork(_ context.Context, logger slog.Logger, addrs []netaddr.IPPrefix) (*WireguardNetwork, error) {
	private := key.NewNode()

	fmt.Println("my addr", addrs[0].String())
	idhash := fnv.New64()
	_, _ = idhash.Write([]byte(private.Public().String()))
	netMap := &netmap.NetworkMap{
		NodeKey:    private.Public(),
		PrivateKey: private,
		// Name:       "workyspace",
		Addresses: addrs,
		// Don't use this for now ...
		// MachineKey: key.NewMachine().Public(),
		PacketFilter: []filter.Match{{
			IPProto: []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv4, ipproto.ICMPv6},
			Srcs: []netaddr.IPPrefix{
				netaddr.IPPrefixFrom(netaddr.IPv4(0, 0, 0, 0), 0),
				netaddr.IPPrefixFrom(netaddr.IPv6Unspecified(), 0),
			},
			Dsts: []filter.NetPortRange{
				{
					Net: netaddr.IPPrefixFrom(netaddr.IPv4(0, 0, 0, 0), 0),
					Ports: filter.PortRange{
						First: 0,
						Last:  65535,
					},
				},
				{
					Net: netaddr.IPPrefixFrom(netaddr.IPv6Unspecified(), 0),
					Ports: filter.PortRange{
						First: 0,
						Last:  65535,
					},
				},
			},
			Caps: []filter.CapMatch{},
		}},
	}
	netMap.SelfNode = &tailcfg.Node{
		ID:       tailcfg.NodeID(idhash.Sum64()),
		StableID: tailcfg.StableNodeID(private.Public().String()),
		// Name:       "me.coder.com.",
		Key:        netMap.PrivateKey.Public(),
		Addresses:  netMap.Addresses,
		AllowedIPs: append(netMap.Addresses, netaddr.MustParseIPPrefix("::/0")),
		Endpoints:  []string{},
		DERP:       "127.3.3.40:9",
	}

	linkMon, err := monitor.New(logf)
	if err != nil {
		return nil, xerrors.Errorf("create link monitor: %w", err)
	}

	netns.SetEnabled(false)
	dialer := new(tsdial.Dialer)
	dialer.Logf = logf
	e, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		LinkMonitor: linkMon,
		Dialer:      dialer,
	})
	if err != nil {
		return nil, xerrors.Errorf("create wgengine: %w", err)
	}

	ig, _ := e.(wgengine.InternalsGetter)
	tunDev, magicConn, dnsMgr, ok := ig.GetInternals()
	if !ok {
		return nil, xerrors.New("engine is not wgengine.InternalsGetter failed")
	}

	// This can't error.
	_ = magicConn.SetPrivateKey(private)
	netMap.SelfNode.DiscoKey = magicConn.DiscoPublicKey()

	http.DefaultServeMux.HandleFunc("/debug/magicsock", magicConn.ServeHTTPDebug)

	ns, err := netstack.Create(logf, tunDev, e, magicConn, dialer, dnsMgr)
	if err != nil {
		return nil, xerrors.Errorf("create netstack: %w", err)
	}

	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	dialer.UseNetstackForIP = func(ip netaddr.IP) bool {
		_, ok := e.PeerForIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netaddr.IPPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	err = ns.Start()
	if err != nil {
		return nil, xerrors.Errorf("start netstack: %w", err)
	}
	e = wgengine.NewWatchdog(e)

	cfg, err := nmcfg.WGCfg(netMap, logf, netmap.AllowSingleHosts|netmap.AllowSubnetRoutes, tailcfg.StableNodeID("nBBoJZ5CNTRL"))
	if err != nil {
		return nil, xerrors.Errorf("create wgcfg: %w", err)
	}

	rtr := &router.Config{
		LocalAddrs: cfg.Addresses,
	}

	err = e.Reconfig(cfg, rtr, &dns.Config{}, &tailcfg.Debug{})
	if err != nil {
		return nil, xerrors.Errorf("reconfig: %w", err)
	}

	e.SetDERPMap(derpMap)
	e.SetNetworkMap(func() *netmap.NetworkMap {
		netMap := *netMap
		return &netMap
	}())

	ipb := netaddr.IPSetBuilder{}
	ipb.AddPrefix(netMap.Addresses[0])
	ips, _ := ipb.IPSet()

	iplb := netaddr.IPSetBuilder{}
	ipl, _ := iplb.IPSet()
	e.SetFilter(filter.New(netMap.PacketFilter, ips, ipl, nil, logf))

	wn := &WireguardNetwork{
		logger:    logger,
		Private:   private,
		Disco:     magicConn.DiscoPublicKey(),
		Engine:    e,
		Netstack:  ns,
		Magic:     magicConn,
		netMap:    netMap,
		listeners: map[listenKey]*listener{},
	}
	ns.ForwardTCPIn = wn.forwardTCP

	return wn, nil
}

func (wn *WireguardNetwork) forwardTCP(c net.Conn, port uint16) {
	wn.mu.Lock()
	ln, ok := wn.listeners[listenKey{"tcp", "", fmt.Sprint(port)}]
	wn.mu.Unlock()
	if !ok {
		// No listener added, forward to host.
		wn.forwardTCPLocal(c, port)
		return
	}

	t := time.NewTimer(time.Second)
	defer t.Stop()
	select {
	case ln.conn <- c:
	case <-t.C:
		_ = c.Close()
	}
}

func (wn *WireguardNetwork) forwardTCPLocal(c net.Conn, port uint16) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer c.Close()

	dialAddrStr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	var stdDialer net.Dialer
	server, err := stdDialer.DialContext(ctx, "tcp", dialAddrStr)
	if err != nil {
		wn.logger.Debug(ctx, "dial local port", slog.F("port", port), slog.Error(err))
		return
	}
	defer server.Close()

	// backendLocalAddr := server.LocalAddr().(*net.TCPAddr)
	// backendLocalIPPort, _ := netaddr.FromStdAddr(backendLocalAddr.IP, backendLocalAddr.Port, backendLocalAddr.Zone)
	// wn.Engine.RegisterIPPortIdentity(backendLocalIPPort, c.RemoteAddr())
	// defer wn.Engine.UnregisterIPPortIdentity(backendLocalIPPort)

	connClosed := make(chan error, 2)
	go func() {
		_, err := io.Copy(server, c)
		connClosed <- err
	}()
	go func() {
		_, err := io.Copy(c, server)
		connClosed <- err
	}()
	err = <-connClosed
	if err != nil {
		wn.logger.Debug(ctx, "proxy connection closed with error", slog.Error(err))
	}
	wn.logger.Debug(ctx, "forwarded connection closed", slog.F("local_addr", dialAddrStr))
}

func (wn *WireguardNetwork) Close() error {
	_ = wn.Netstack.Close()
	wn.Engine.Close()

	return nil
}

func (wn *WireguardNetwork) AddPeer(peer WireguardPeerMessage) error {
	for _, p := range wn.netMap.Peers {
		if p.Key == peer.Public {
			continue
		}
	}

	peers := append(([]*tailcfg.Node)(nil), wn.netMap.Peers...)
	idhash := fnv.New64()
	_, _ = idhash.Write([]byte(peer.Public.String()))
	peers = append(peers, &tailcfg.Node{
		ID:         tailcfg.NodeID(idhash.Sum64()),
		StableID:   tailcfg.StableNodeID(peer.Public.String()),
		Name:       peer.Public.String() + ".com",
		Key:        peer.Public,
		DiscoKey:   peer.Disco,
		Addresses:  []netaddr.IPPrefix{netaddr.IPPrefixFrom(peer.IPv6, 128)},
		AllowedIPs: []netaddr.IPPrefix{netaddr.IPPrefixFrom(peer.IPv6, 128)},
		DERP:       "127.3.3.40:9",
		Endpoints:  []string{"127.3.3.40:9"},
	})

	wn.netMap.Peers = peers

	cfg, err := nmcfg.WGCfg(wn.netMap, logf, netmap.AllowSingleHosts|netmap.AllowSubnetRoutes, tailcfg.StableNodeID("nBBoJZ5CNTRL"))
	if err != nil {
		return xerrors.Errorf("create wgcfg: %w", err)
	}

	rtr := &router.Config{
		LocalAddrs: cfg.Addresses,
	}

	err = wn.Engine.Reconfig(cfg, rtr, &dns.Config{}, &tailcfg.Debug{})
	if err != nil {
		return xerrors.Errorf("reconfig: %w", err)
	}

	wn.Engine.SetNetworkMap(func() *netmap.NetworkMap {
		netMap := *wn.netMap
		return &netMap
	}())

	return nil
}

func (wn *WireguardNetwork) Ping(peer WireguardPeerMessage) *ipnstate.PingResult {
	ch := make(chan *ipnstate.PingResult)
	wn.Engine.Ping(peer.IPv6, tailcfg.PingDisco, func(pr *ipnstate.PingResult) {
		ch <- pr
	})

	return <-ch
}

func (wn *WireguardNetwork) Listen(network, addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, xerrors.Errorf("split addr host port: %w", err)
	}

	lkey := listenKey{network, host, port}
	ln := &listener{
		wn:   wn,
		key:  lkey,
		addr: addr,

		conn: make(chan net.Conn, 1),
	}

	wn.mu.Lock()
	defer wn.mu.Unlock()

	if _, ok := wn.listeners[lkey]; ok {
		return nil, xerrors.Errorf("listener already open for %s, %s", network, addr)
	}
	wn.listeners[lkey] = ln

	return ln, nil
}

type listenKey struct {
	network string
	host    string
	port    string
}

type listener struct {
	wn   *WireguardNetwork
	key  listenKey
	addr string
	conn chan net.Conn
}

func (ln *listener) Accept() (net.Conn, error) {
	c, ok := <-ln.conn
	if !ok {
		return nil, xerrors.Errorf("tsnet: %w", net.ErrClosed)
	}
	return c, nil
}

func (ln *listener) Addr() net.Addr { return addr{ln} }
func (ln *listener) Close() error {
	ln.wn.mu.Lock()
	defer ln.wn.mu.Unlock()

	if v, ok := ln.wn.listeners[ln.key]; ok && v == ln {
		delete(ln.wn.listeners, ln.key)
		close(ln.conn)
	}

	return nil
}

type addr struct{ ln *listener }

func (a addr) Network() string { return a.ln.key.network }
func (a addr) String() string  { return a.ln.addr }

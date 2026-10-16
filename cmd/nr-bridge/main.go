/**
 * SPDX-License-Identifier: Apache-2.0
 */

// nr-bridge connects the gNBs and UEs simulated by ns-3 (5G-LENA) to one or more 5G cores.
//
// For each simulated gNB, it establishes the NGAP association with the AMF of the core
// serving the gNB PLMN. For each simulated UE, it runs the UE NAS procedures (registration,
// authentication, security mode, PDU session establishment) and the gNB NGAP procedures on
// behalf of the simulation, and reports to ns-3 the user-plane parameters of the PDU
// session (UE address, UPF address and TEIDs, QoS flow). The user plane (GTP-U on N3) is
// handled by ns-3. A UE attaching through a gNB whose PLMN is not the UE home PLMN
// registers in that (visited) core, which reaches the home core through the SEPPs.
//
// The control channel with ns-3 carries one JSON object per UDP datagram:
//
//	ns-3 -> bridge: {"msg":"gnb_setup","gnb":1,"mcc":"999","mnc":"70","tac":1,"n3":"10.200.1.2"}
//	bridge -> ns-3: {"msg":"gnb_ready","gnb":1} | {"msg":"gnb_failed","gnb":1,"reason":"..."}
//	ns-3 -> bridge: {"msg":"ue_attach","gnb":1,"rnti":1,"imsi":"999700000000001"}
//	bridge -> ns-3: {"msg":"ue_ready","gnb":1,"rnti":1,"imsi":"...","ue_ip":"10.45.0.2",
//	                 "upf":"10.100.0.10","ul_teid":1,"dl_teid":1,"qfi":1,"five_qi":9,
//	                 "dns":"8.8.8.8,8.8.4.4"}
//	              | {"msg":"ue_failed","gnb":1,"rnti":1,"imsi":"...","reason":"..."}
//	ns-3 -> bridge: {"msg":"ue_release","gnb":1,"rnti":1}
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"my5G-RANTester/config"
	gnbContext "my5G-RANTester/internal/control_test_engine/gnb/context"
	gnbNasService "my5G-RANTester/internal/control_test_engine/gnb/nas/service"
	"my5G-RANTester/internal/control_test_engine/gnb/ngap"
	"my5G-RANTester/internal/control_test_engine/gnb/ngap/trigger"
	"my5G-RANTester/internal/control_test_engine/procedures"
	"my5G-RANTester/internal/control_test_engine/ue"
	ueContext "my5G-RANTester/internal/control_test_engine/ue/context"
	gtpService "my5G-RANTester/internal/control_test_engine/ue/gtp/service"
	"my5G-RANTester/internal/control_test_engine/ue/scenario"

	log "github.com/sirupsen/logrus"
)

// Core is a 5G core network the simulated gNBs can be connected to.
type Core struct {
	Mcc string `json:"mcc"`
	Mnc string `json:"mnc"`
	// Amf is the NGAP address of the AMF ("ip:port").
	Amf string `json:"amf"`
	// LocalN2 is the local address used for the SCTP associations with the AMF.
	LocalN2 string `json:"local_n2"`
}

// Subscriber holds the credentials of the simulated UEs, shared with the core databases.
type Subscriber struct {
	Key string `json:"key"`
	Opc string `json:"opc"`
	Amf string `json:"amf"`
	Sqn string `json:"sqn"`
}

// Config is the bridge configuration.
type Config struct {
	// Listen is the address of the control channel with ns-3 ("ip:port").
	Listen string `json:"listen"`
	Cores  []Core `json:"cores"`
	// Subscriber holds the default credentials; Subscribers overrides them per IMSI.
	Subscriber  Subscriber            `json:"subscriber"`
	Subscribers map[string]Subscriber `json:"subscribers"`
	Dnn         string                `json:"dnn"`
	Sst         int                   `json:"sst"`
	Sd          string                `json:"sd"`
	// MncLength maps a MCC to the length of its MNCs, to split the IMSIs (default 2).
	MncLength map[string]int `json:"mnc_length"`
	// Sepp, if set, makes the bridge the SEPP and the home network (AUSF, UDM) of the UEs of
	// a core network of ns-3, for the visited networks that roam with it.
	Sepp *SeppConfig `json:"sepp"`
}

// Message is a control message exchanged with ns-3.
type Message struct {
	Msg    string `json:"msg"`
	Gnb    uint32 `json:"gnb"`
	Mcc    string `json:"mcc,omitempty"`
	Mnc    string `json:"mnc,omitempty"`
	Tac    uint32 `json:"tac,omitempty"`
	N3     string `json:"n3,omitempty"`
	Rnti   uint16 `json:"rnti,omitempty"`
	Imsi   string `json:"imsi,omitempty"`
	UeIp   string `json:"ue_ip,omitempty"`
	Upf    string `json:"upf,omitempty"`
	UlTeid uint32 `json:"ul_teid,omitempty"`
	DlTeid uint32 `json:"dl_teid,omitempty"`
	Qfi    int64  `json:"qfi,omitempty"`
	FiveQi int64  `json:"five_qi,omitempty"`
	Dns    string `json:"dns,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type ueKey struct {
	gnb  uint32
	rnti uint16
}

type simUe struct {
	key      ueKey
	imsi     string
	commands chan procedures.UeTesterMessage
	ready    bool
	done     chan struct{} // closed when the UE terminates
}

// Bridge keeps the state of the simulated gNBs and UEs.
type Bridge struct {
	cfg  Config
	conn *net.UDPConn

	mu     sync.Mutex
	peers  map[uint32]*net.UDPAddr // control address of each gNB in ns-3, from its messages
	gnbs   map[uint32]*gnbContext.GNBContext
	setups map[uint32]bool // gNBs whose NG setup is in progress
	ues    map[ueKey]*simUe
	byMsin map[string]*simUe
	nextId int
	wg     sync.WaitGroup
	home   *homeNetwork // the home network behind the SEPP, if any
}

func main() {
	configPath := flag.String("config", "nr-bridge.json", "configuration file")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal("[BRIDGE] Cannot read configuration: ", err)
	}
	b := &Bridge{
		peers:  make(map[uint32]*net.UDPAddr),
		gnbs:   make(map[uint32]*gnbContext.GNBContext),
		setups: make(map[uint32]bool),
		ues:    make(map[ueKey]*simUe),
		byMsin: make(map[string]*simUe),
	}
	if err := json.Unmarshal(data, &b.cfg); err != nil {
		log.Fatal("[BRIDGE] Invalid configuration: ", err)
	}
	gtpService.OnPduSessionReady = b.onPduSessionReady
	if b.cfg.Sepp != nil {
		b.home = b.startSepp(*b.cfg.Sepp)
		// the core network of ns-3 deletes the session of the UE in its networks
		b.home.onUeAmf = func(supi string) {
			b.send(Message{Msg: "home_registration", Gnb: 0, Imsi: strings.TrimPrefix(supi, "imsi-")})
		}
	}

	addr, err := net.ResolveUDPAddr("udp", b.cfg.Listen)
	if err != nil {
		log.Fatal("[BRIDGE] Invalid listen address: ", err)
	}
	b.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal("[BRIDGE] Cannot listen: ", err)
	}
	log.Info("[BRIDGE] Waiting for ns-3 on ", b.cfg.Listen)

	buf := make([]byte, 65535)
	for {
		n, from, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal("[BRIDGE] Control channel error: ", err)
		}
		var msg Message
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			log.Warn("[BRIDGE] Ignoring invalid message: ", err)
			continue
		}
		b.mu.Lock()
		b.peers[msg.Gnb] = from
		b.mu.Unlock()
		switch msg.Msg {
		case "gnb_setup":
			go b.gnbSetup(msg)
		case "ue_attach":
			go b.ueAttach(msg)
		case "ue_release":
			go b.ueRelease(msg)
		case "home_setup":
			// the core network of ns-3 behind the SEPP, reached at gNB 0
			log.Info("[BRIDGE] Home network of the UEs of ns-3: PLMN ", msg.Mcc, "/", msg.Mnc)
		case "home_cancel":
			go b.homeCancel(msg)
		default:
			log.Warn("[BRIDGE] Ignoring unknown message ", msg.Msg)
		}
	}
}

func (b *Bridge) send(msg Message) {
	data, _ := json.Marshal(msg)
	b.mu.Lock()
	peer := b.peers[msg.Gnb]
	b.mu.Unlock()
	if peer == nil {
		log.Error("[BRIDGE] No address for gNB ", msg.Gnb)
		return
	}
	if _, err := b.conn.WriteToUDP(data, peer); err != nil {
		log.Error("[BRIDGE] Cannot send to ns-3: ", err)
	}
}

func (b *Bridge) findCore(mcc, mnc string) *Core {
	for i := range b.cfg.Cores {
		if b.cfg.Cores[i].Mcc == mcc && b.cfg.Cores[i].Mnc == mnc {
			return &b.cfg.Cores[i]
		}
	}
	return nil
}

func (b *Bridge) gnbSetup(msg Message) {
	fail := func(reason string) {
		log.Error("[BRIDGE] gNB ", msg.Gnb, ": ", reason)
		b.send(Message{Msg: "gnb_failed", Gnb: msg.Gnb, Reason: reason})
	}
	b.mu.Lock()
	_, exists := b.gnbs[msg.Gnb]
	inProgress := b.setups[msg.Gnb]
	if !exists && !inProgress {
		b.setups[msg.Gnb] = true
	}
	b.mu.Unlock()
	if exists {
		b.send(Message{Msg: "gnb_ready", Gnb: msg.Gnb})
		return
	}
	if inProgress {
		// a retransmission of gnb_setup: the setup in progress answers it
		return
	}
	defer func() {
		b.mu.Lock()
		delete(b.setups, msg.Gnb)
		b.mu.Unlock()
	}()
	core := b.findCore(msg.Mcc, msg.Mnc)
	if core == nil {
		fail(fmt.Sprintf("no core configured for PLMN %s/%s", msg.Mcc, msg.Mnc))
		return
	}
	amf, err := netip.ParseAddrPort(core.Amf)
	if err != nil {
		fail("invalid AMF address: " + err.Error())
		return
	}
	n2, err := netip.ParseAddrPort(core.LocalN2)
	if err != nil {
		fail("invalid local N2 address: " + err.Error())
		return
	}
	n3, err := netip.ParseAddr(msg.N3)
	if err != nil {
		fail("invalid N3 address: " + err.Error())
		return
	}

	gnb := &gnbContext.GNBContext{}
	gnb.NewRanGnbContext(fmt.Sprintf("%06x", msg.Gnb), msg.Mcc, msg.Mnc, fmt.Sprintf("%06x", msg.Tac),
		fmt.Sprintf("%02x", b.cfg.Sst), b.cfg.Sd, n2, netip.AddrPortFrom(n3, 2152))
	gnbAmf := gnb.NewGnBAmf(amf)
	if err := ngap.InitConn(gnbAmf, gnb); err != nil {
		fail("cannot connect to the AMF: " + err.Error())
		return
	}
	trigger.SendNgSetupRequest(gnb, gnbAmf)
	deadline := time.Now().Add(5 * time.Second)
	for gnbAmf.GetState() != 0x01 { // active
		if time.Now().After(deadline) {
			gnb.Terminate()
			fail("NG setup timed out")
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	gnbNasService.InitServer(gnb)

	b.mu.Lock()
	b.gnbs[msg.Gnb] = gnb
	b.mu.Unlock()
	log.Info("[BRIDGE] gNB ", msg.Gnb, " connected to the core of PLMN ", msg.Mcc, "/", msg.Mnc)
	b.send(Message{Msg: "gnb_ready", Gnb: msg.Gnb})
}

// splitImsi returns the MCC, MNC and MSIN of an IMSI.
func (b *Bridge) splitImsi(imsi string) (string, string, string, error) {
	if len(imsi) < 6 {
		return "", "", "", fmt.Errorf("invalid IMSI %q", imsi)
	}
	mcc := imsi[:3]
	mncLength := 2
	if l, ok := b.cfg.MncLength[mcc]; ok {
		mncLength = l
	}
	return mcc, imsi[3 : 3+mncLength], imsi[3+mncLength:], nil
}

func (b *Bridge) ueAttach(msg Message) {
	key := ueKey{msg.Gnb, msg.Rnti}
	fail := func(reason string) {
		log.Error("[BRIDGE] UE ", msg.Imsi, ": ", reason)
		b.send(Message{Msg: "ue_failed", Gnb: msg.Gnb, Rnti: msg.Rnti, Imsi: msg.Imsi, Reason: reason})
	}
	mcc, mnc, msin, err := b.splitImsi(msg.Imsi)
	if err != nil {
		fail(err.Error())
		return
	}
	b.mu.Lock()
	gnb := b.gnbs[msg.Gnb]
	previous := b.byMsin[msin]
	b.mu.Unlock()
	if gnb == nil {
		fail(fmt.Sprintf("gNB %d is not connected", msg.Gnb))
		return
	}
	if previous != nil {
		// The UE registers again, e.g., after having been served by another network. As a real
		// UE that left the coverage of its previous network, it does not deregister there: its
		// previous context is dropped, and the new registration replaces it in the core
		// networks. A deregistration would race with the new registration.
		log.Info("[BRIDGE] UE ", msg.Imsi, " registers again: dropping its previous context")
		b.forget(previous)
		previous.commands <- procedures.UeTesterMessage{Type: procedures.Kill}
		select {
		case <-previous.done:
		case <-time.After(3 * time.Second):
			log.Warn("[BRIDGE] UE ", msg.Imsi, ": previous context not released in time")
		}
	}
	sub := b.cfg.Subscriber
	if s, ok := b.cfg.Subscribers[msg.Imsi]; ok {
		sub = s
	}

	var cfg config.Config
	cfg.Ue = config.Ue{
		Msin:             msin,
		Key:              sub.Key,
		Opc:              sub.Opc,
		Amf:              sub.Amf,
		Sqn:              sub.Sqn,
		Dnn:              b.cfg.Dnn,
		ProtectionScheme: 0,
		RoutingIndicator: "0000",
		Hplmn:            config.Hplmn{Mcc: mcc, Mnc: mnc},
		Snssai:           config.Snssai{Sst: b.cfg.Sst, Sd: b.cfg.Sd},
		Integrity:        config.Integrity{Nia1: true, Nia2: true},
		Ciphering:        config.Ciphering{Nea0: true, Nea1: true, Nea2: true},
		TunnelMode:       config.TunnelDisabled,
	}

	commands := make(chan procedures.UeTesterMessage, 4)
	u := &simUe{key: key, imsi: msg.Imsi, commands: commands, done: make(chan struct{})}
	b.mu.Lock()
	b.nextId++
	id := b.nextId
	b.ues[key] = u
	b.byMsin[msin] = u
	b.mu.Unlock()

	b.wg.Add(1)
	states := ue.NewUE(cfg, id, commands, gnb.GetInboundChannel(), &b.wg)
	commands <- procedures.UeTesterMessage{Type: procedures.Registration}
	go b.followUe(u, states)
}

// followUe requests the PDU session once the UE is registered, and reports the failures. It
// consumes the UE state changes until the UE terminates, as the UE blocks on reporting them.
func (b *Bridge) followUe(u *simUe, states chan scenario.ScenarioMessage) {
	defer close(u.done)
	registered := false
	timeout := time.After(10 * time.Second)
	isReady := func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return u.ready
	}
	for {
		select {
		case state, ok := <-states:
			if !ok {
				return
			}
			switch state.StateChange {
			case ueContext.MM5G_REGISTERED:
				if !registered {
					registered = true
					u.commands <- procedures.UeTesterMessage{Type: procedures.NewPDUSession}
				}
			case ueContext.MM5G_NULL:
				if !isReady() {
					b.send(Message{Msg: "ue_failed", Gnb: u.key.gnb, Rnti: u.key.rnti, Imsi: u.imsi,
						Reason: "registration failed"})
				}
				b.forget(u)
				return
			}
		case <-timeout:
			timeout = nil
			if !isReady() {
				b.send(Message{Msg: "ue_failed", Gnb: u.key.gnb, Rnti: u.key.rnti, Imsi: u.imsi,
					Reason: "timeout"})
				b.forget(u)
				u.commands <- procedures.UeTesterMessage{Type: procedures.Kill}
			}
		}
	}
}

func (b *Bridge) onPduSessionReady(ueCtx *ueContext.UEContext, pdu *ueContext.UEPDUSession) {
	b.mu.Lock()
	u := b.byMsin[ueCtx.GetMsin()]
	if u != nil {
		u.ready = true
	}
	b.mu.Unlock()
	if u == nil {
		log.Warn("[BRIDGE] PDU session of unknown UE ", ueCtx.GetMsin())
		return
	}
	g := pdu.GnbPduSession
	msg := Message{
		Msg:    "ue_ready",
		Gnb:    u.key.gnb,
		Rnti:   u.key.rnti,
		Imsi:   u.imsi,
		UeIp:   pdu.GetIp(),
		Upf:    g.GetUpfIp(),
		UlTeid: g.GetTeidUplink(),
		DlTeid: g.GetTeidDownlink(),
		Qfi:    g.GetQosId(),
		FiveQi: g.GetFiveQI(),
		Dns:    strings.Join(pdu.GetDnsServers(), ","),
	}
	log.Info("[BRIDGE] UE ", u.imsi, " ready: ", msg.UeIp, " UPF ", msg.Upf, " TEIDs ", msg.UlTeid, "/",
		msg.DlTeid)
	b.send(msg)
}

func (b *Bridge) forget(u *simUe) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ues[u.key] == u {
		delete(b.ues, u.key)
	}
	for msin, v := range b.byMsin {
		if v == u {
			delete(b.byMsin, msin)
		}
	}
}

// homeCancel handles the attachment of a UE in a core network of ns-3, its home network: the
// visited network that served it deregisters it, and its context in the bridge is dropped.
func (b *Bridge) homeCancel(msg Message) {
	if b.home != nil {
		b.home.deregister("imsi-" + msg.Imsi)
	}
	_, _, msin, err := b.splitImsi(msg.Imsi)
	if err != nil {
		return
	}
	b.mu.Lock()
	u := b.byMsin[msin]
	b.mu.Unlock()
	if u != nil {
		b.forget(u)
		u.commands <- procedures.UeTesterMessage{Type: procedures.Kill}
	}
}

func (b *Bridge) ueRelease(msg Message) {
	b.mu.Lock()
	u := b.ues[ueKey{msg.Gnb, msg.Rnti}]
	b.mu.Unlock()
	if u == nil {
		return
	}
	u.commands <- procedures.UeTesterMessage{Type: procedures.Terminate}
	b.forget(u)
}

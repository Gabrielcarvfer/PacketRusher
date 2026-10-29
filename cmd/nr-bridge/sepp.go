package main

// The SEPP of a home network emulated by nr-bridge, for the UEs of a core network of ns-3: the
// SEPPs of the visited networks (e.g., Open5GS) reach the home network through N32 (TS 29.573),
// as for any other roaming partner, and nr-bridge answers as its AUSF (5G-AKA, TS 33.501) and its
// UDM (UE context management and subscriber data, TS 29.503), after its NRF has made them known
// (discovery, TS 29.510).
//
// N32-c only negotiates the security capability and the PLMNs of each side. N32-f carries the SBI
// requests of the visited network, with their target in the 3gpp-Sbi-Target-apiRoot header. Both
// run over HTTP/2 without TLS, as in the roaming example of Open5GS.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// PlmnId is the PLMN of a network.
type PlmnId struct {
	Mcc string `json:"mcc"`
	Mnc string `json:"mnc"`
}

// SeppConfig configures the SEPP of the home network emulated by nr-bridge, and the
// subscription data of its UEs (their credentials are the subscribers of the bridge).
type SeppConfig struct {
	// Fqdn is the name of the SEPP in the N32-c handshake.
	Fqdn string `json:"fqdn"`
	// N32c and N32f are the addresses of the N32-c and N32-f servers ("ip:port").
	N32c string `json:"n32c"`
	N32f string `json:"n32f"`
	// Plmns are the PLMNs of the home network.
	Plmns []PlmnId `json:"plmns"`
	// FiveQi and Ambr are the 5QI of the default QoS flow and the AMBR of the UEs.
	FiveQi int    `json:"five_qi"`
	Ambr   string `json:"ambr"`
	// Peers are the SEPPs of the visited networks, for the requests of the home network.
	Peers []SeppPeer `json:"peers"`
}

// SeppPeer is the SEPP of a visited network.
type SeppPeer struct {
	Plmn PlmnId `json:"plmn"`
	// N32f is the URI of its N32-f server.
	N32f string `json:"n32f"`
}

// authContext is a 5G-AKA authentication in progress.
type authContext struct {
	supi     string
	xresStar []byte
	kseaf    []byte
}

// homeNetwork is the AUSF and the UDM of the home network behind the SEPP.
type homeNetwork struct {
	bridge *Bridge
	cfg    SeppConfig

	mu      sync.Mutex
	sqn     map[string]uint64       // last sequence number, by SUPI
	auths   map[string]*authContext // authentications, by identifier
	nextId  int
	amfRegs map[string]json.RawMessage // AMF registration, by SUPI
	smfRegs map[string]json.RawMessage // SMF registrations, by SUPI and PDU session
	sdmSubs map[string]string          // SDM subscriptions: identifier to SUPI
	onUeAmf func(supi string)          // the UE registered in a visited network
	nfIds   map[string]string          // identifiers of the network functions, by type
}

// newUuid returns a random UUID (version 4).
func newUuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// nfServices are the services of the network functions of the home network.
var nfServices = map[string][]string{
	"AUSF": {"nausf-auth"},
	"UDM":  {"nudm-sdm", "nudm-uecm", "nudm-ueau"},
}

// apiVersions are the major versions of the APIs of the services, as in their URIs.
var apiVersions = map[string]string{
	"nausf-auth": "v1",
	"nudm-sdm":   "v2",
	"nudm-uecm":  "v1",
	"nudm-ueau":  "v1",
}

// startSepp starts the N32-c and N32-f servers of the SEPP.
func (b *Bridge) startSepp(cfg SeppConfig) *homeNetwork {
	if cfg.FiveQi == 0 {
		cfg.FiveQi = 9
	}
	if cfg.Ambr == "" {
		cfg.Ambr = "1000000 Kbps"
	}
	h := &homeNetwork{
		bridge:  b,
		cfg:     cfg,
		sqn:     make(map[string]uint64),
		auths:   make(map[string]*authContext),
		amfRegs: make(map[string]json.RawMessage),
		smfRegs: make(map[string]json.RawMessage),
		sdmSubs: make(map[string]string),
		nfIds:   make(map[string]string),
	}
	for nfType := range nfServices {
		h.nfIds[nfType] = newUuid()
	}

	n32c := http.NewServeMux()
	n32c.HandleFunc("POST /n32c-handshake/v1/exchange-capability", h.exchangeCapability)
	n32f := http.NewServeMux()
	n32f.HandleFunc("GET /nnrf-disc/v1/nf-instances", h.discovery)
	n32f.HandleFunc("POST /nausf-auth/v1/ue-authentications", h.ueAuthentication)
	n32f.HandleFunc("PUT /nausf-auth/v1/ue-authentications/{id}/5g-aka-confirmation", h.akaConfirmation)
	n32f.HandleFunc("DELETE /nausf-auth/v1/ue-authentications/{id}/5g-aka-confirmation", h.noContent)
	n32f.HandleFunc("PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", h.amfRegistration)
	n32f.HandleFunc("PATCH /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", h.amfModification)
	n32f.HandleFunc("PUT /nudm-uecm/v1/{supi}/registrations/smf-registrations/{id}", h.smfRegistration)
	n32f.HandleFunc("DELETE /nudm-uecm/v1/{supi}/registrations/smf-registrations/{id}", h.smfDeregistration)
	n32f.HandleFunc("GET /nudm-sdm/v2/{supi}/{dataset}", h.subscriptionData)
	n32f.HandleFunc("POST /nudm-sdm/v2/{supi}/sdm-subscriptions", h.sdmSubscribe)
	n32f.HandleFunc("DELETE /nudm-sdm/v2/{supi}/sdm-subscriptions/{id}", h.sdmUnsubscribe)
	n32f.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Warn("[SEPP] Unsupported request ", r.Method, " ", r.URL.Path)
		problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND")
	})

	for _, server := range []struct {
		name    string
		addr    string
		handler http.Handler
	}{{"N32-c", cfg.N32c, n32c}, {"N32-f", cfg.N32f, n32f}} {
		srv := &http.Server{Addr: server.addr, Handler: h2c.NewHandler(logged(server.handler), &http2.Server{})}
		name := server.name
		go func() {
			log.Info("[SEPP] ", name, " server on ", srv.Addr)
			if err := srv.ListenAndServe(); err != nil {
				log.Fatal("[SEPP] ", name, " server: ", err)
			}
		}()
	}
	return h
}

// logged logs the requests received by a handler.
func logged(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info("[SEPP] ", r.Method, " ", r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}

// reply sends a JSON response.
func reply(w http.ResponseWriter, status int, body any) {
	data, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// problem sends a problem details response (RFC 7807).
func problem(w http.ResponseWriter, status int, cause string) {
	data, _ := json.Marshal(map[string]any{"status": status, "cause": cause})
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	w.Write(data)
}

// apiRoot returns the API root of the target of a request, to build the URIs of the resources.
func apiRoot(r *http.Request) string {
	if root := r.Header.Get("3gpp-Sbi-Target-apiRoot"); root != "" {
		return strings.TrimSuffix(root, "/")
	}
	return "http://" + r.Host
}

// exchangeCapability answers the N32-c handshake of a visited SEPP.
func (h *homeNetwork) exchangeCapability(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sender                     string   `json:"sender"`
		SupportedSecCapabilityList []string `json:"supportedSecCapabilityList"`
		PlmnIdList                 []PlmnId `json:"plmnIdList"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT")
		return
	}
	log.Info("[SEPP] N32 handshake with ", req.Sender, " of ", req.PlmnIdList)
	reply(w, http.StatusOK, map[string]any{
		"sender":                        h.cfg.Fqdn,
		"selectedSecCapability":         "TLS",
		"3GppSbiTargetApiRootSupported": true,
		"plmnIdList":                    h.cfg.Plmns,
		"supportedFeatures":             "1",
	})
}

// fqdn returns the FQDN of a network function of the home network (TS 23.003, 28.3.2.3).
func (h *homeNetwork) fqdn(nfType string) string {
	plmn := h.cfg.Plmns[0]
	mnc := plmn.Mnc
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	return strings.ToLower(nfType) + ".5gc.mnc" + mnc + ".mcc" + plmn.Mcc + ".3gppnetwork.org"
}

// deregister notifies the AMF of the visited network that serves a UE that the UE is no longer
// registered there (Nudm_UECM_DeregistrationNotification), e.g., since it attached in a core
// network of ns-3, through the SEPP of the visited network.
func (h *homeNetwork) deregister(supi string) {
	h.mu.Lock()
	registration, ok := h.amfRegs[supi]
	delete(h.amfRegs, supi)
	for key := range h.smfRegs {
		if strings.HasPrefix(key, supi+"/") {
			delete(h.smfRegs, key)
		}
	}
	h.mu.Unlock()
	if !ok {
		return
	}
	var amf struct {
		DeregCallbackUri string `json:"deregCallbackUri"`
		Guami            struct {
			PlmnId PlmnId `json:"plmnId"`
		} `json:"guami"`
	}
	json.Unmarshal(registration, &amf)
	callback, err := url.Parse(amf.DeregCallbackUri)
	if err != nil || callback.Host == "" {
		log.Warn("[SEPP] No callback to deregister ", supi)
		return
	}
	var peer *SeppPeer
	for i := range h.cfg.Peers {
		if h.cfg.Peers[i].Plmn == amf.Guami.PlmnId {
			peer = &h.cfg.Peers[i]
		}
	}
	if peer == nil {
		log.Warn("[SEPP] No SEPP for the visited network ", amf.Guami.PlmnId, " of ", supi)
		return
	}
	body, _ := json.Marshal(map[string]string{
		"deregReason": "UE_REGISTRATION_AREA_CHANGE",
		"accessType":  "3GPP_ACCESS",
	})
	req, _ := http.NewRequest("POST", strings.TrimSuffix(peer.N32f, "/")+callback.RequestURI(),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("3gpp-Sbi-Target-apiRoot", callback.Scheme+"://"+callback.Host)
	// a notification to a callback URI, which the SCP routes without discovery (TS 29.500)
	req.Header.Set("3gpp-Sbi-Callback", "Nudm_UECM_DeregistrationNotification")
	// the type of the network function that sends the request (TS 29.500, 5.2.2.2)
	req.Header.Set("User-Agent", "UDM-"+h.nfIds["UDM"])
	rsp, err := h.client().Do(req)
	if err != nil {
		log.Warn("[SEPP] Deregistration of ", supi, " failed: ", err)
		return
	}
	rsp.Body.Close()
	log.Info("[SEPP] ", supi, " deregistered from the visited network ", amf.Guami.PlmnId,
		": status ", rsp.StatusCode)
}

// client returns an HTTP/2 client without TLS, for the N32-f servers of the peer SEPPs.
func (h *homeNetwork) client() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}
}

// discovery answers the discovery of the network functions of the home network by a visited
// network (Nnrf_NFDiscovery): the AUSF and the UDM emulated by the bridge.
func (h *homeNetwork) discovery(w http.ResponseWriter, r *http.Request) {
	nfType := r.URL.Query().Get("target-nf-type")
	services, ok := nfServices[nfType]
	instances := []any{}
	if ok {
		fqdn := h.fqdn(nfType)
		nfServiceList := []any{}
		for _, name := range services {
			nfServiceList = append(nfServiceList, map[string]any{
				"serviceInstanceId": h.nfIds[nfType] + "-" + name,
				"serviceName":       name,
				"versions":          []any{map[string]string{"apiVersionInUri": apiVersions[name], "apiFullVersion": apiVersions[name][1:] + ".0.0"}},
				"scheme":            "http",
				"nfServiceStatus":   "REGISTERED",
				"fqdn":              fqdn,
			})
		}
		instances = append(instances, map[string]any{
			"nfInstanceId": h.nfIds[nfType],
			"nfType":       nfType,
			"nfStatus":     "REGISTERED",
			"plmnList":     h.cfg.Plmns,
			"fqdn":         fqdn,
			"nfServices":   nfServiceList,
		})
	} else {
		log.Warn("[SEPP] No ", nfType, " in the home network")
	}
	reply(w, http.StatusOK, map[string]any{"validityPeriod": 3600, "nfInstances": instances})
}

// supiOf returns the SUPI ("imsi-...") of a SUPI or of a SUCI with the null protection scheme.
func supiOf(supiOrSuci string) (string, error) {
	if strings.HasPrefix(supiOrSuci, "imsi-") {
		return supiOrSuci, nil
	}
	// suci-0-<mcc>-<mnc>-<routing indicator>-<protection scheme>-<home network key>-<msin>
	parts := strings.Split(supiOrSuci, "-")
	if len(parts) != 8 || parts[0] != "suci" || parts[1] != "0" {
		return "", fmt.Errorf("unsupported SUCI %q", supiOrSuci)
	}
	if parts[5] != "0" {
		return "", fmt.Errorf("unsupported protection scheme in SUCI %q", supiOrSuci)
	}
	return "imsi-" + parts[2] + parts[3] + parts[7], nil
}

// isSubscriber returns whether a SUPI belongs to the home network.
func (h *homeNetwork) isSubscriber(supi string) bool {
	imsi := strings.TrimPrefix(supi, "imsi-")
	for _, plmn := range h.cfg.Plmns {
		if strings.HasPrefix(imsi, plmn.Mcc+plmn.Mnc) {
			return true
		}
	}
	return false
}

// ueAuthentication starts a 5G-AKA authentication (Nausf_UEAuthentication_Authenticate): the
// authentication vector is generated as by the UDM/ARPF, and the AUSF keeps XRES* and KSEAF.
func (h *homeNetwork) ueAuthentication(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SupiOrSuci         string `json:"supiOrSuci"`
		ServingNetworkName string `json:"servingNetworkName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT")
		return
	}
	supi, err := supiOf(req.SupiOrSuci)
	if err != nil || !h.isSubscriber(supi) {
		log.Warn("[SEPP] Unknown UE ", req.SupiOrSuci)
		problem(w, http.StatusNotFound, "USER_NOT_FOUND")
		return
	}
	sub := h.bridge.cfg.Subscriber
	if s, ok := h.bridge.cfg.Subscribers[strings.TrimPrefix(supi, "imsi-")]; ok {
		sub = s
	}
	opc, err1 := hex.DecodeString(sub.Opc)
	k, err2 := hex.DecodeString(sub.Key)
	amf, err3 := hex.DecodeString(sub.Amf)
	if err1 != nil || err2 != nil || err3 != nil {
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE")
		return
	}

	// the sequence number of the home network, from the one of the subscriber
	h.mu.Lock()
	sqn, ok := h.sqn[supi]
	if !ok {
		sqn, _ = strconv.ParseUint(sub.Sqn, 16, 48)
	}
	sqn++
	h.sqn[supi] = sqn
	h.mu.Unlock()
	sqnBytes := make([]byte, 6)
	for i := 0; i < 6; i++ {
		sqnBytes[i] = byte(sqn >> (8 * (5 - i)))
	}

	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	ik, ck, xres, autn, err := milenage.GenerateAKAParameters(opc, k, randBytes, sqnBytes, amf)
	if err != nil {
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE")
		return
	}
	// TS 33.501, annex A: KAUSF, XRES*, HXRES* and KSEAF
	key := append(append([]byte{}, ck...), ik...)
	sn := []byte(req.ServingNetworkName)
	sqnXorAk := autn[:6]
	kausf, _ := ueauth.GetKDFValue(key, ueauth.FC_FOR_KAUSF_DERIVATION, sn, ueauth.KDFLen(sn),
		sqnXorAk, ueauth.KDFLen(sqnXorAk))
	xresStarKdf, _ := ueauth.GetKDFValue(key, ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION, sn,
		ueauth.KDFLen(sn), randBytes, ueauth.KDFLen(randBytes), xres, ueauth.KDFLen(xres))
	xresStar := xresStarKdf[16:]
	hxres := sha256.Sum256(append(append([]byte{}, randBytes...), xresStar...))
	kseaf, _ := ueauth.GetKDFValue(kausf, ueauth.FC_FOR_KSEAF_DERIVATION, sn, ueauth.KDFLen(sn))

	h.mu.Lock()
	h.nextId++
	id := strconv.Itoa(h.nextId)
	h.auths[id] = &authContext{supi: supi, xresStar: xresStar, kseaf: kseaf}
	h.mu.Unlock()
	log.Info("[SEPP] Authentication of ", supi, " from ", req.ServingNetworkName)

	link := apiRoot(r) + "/nausf-auth/v1/ue-authentications/" + id
	w.Header().Set("Location", link)
	reply(w, http.StatusCreated, map[string]any{
		"authType": "5G_AKA",
		"5gAuthData": map[string]string{
			"rand":      hex.EncodeToString(randBytes),
			"hxresStar": hex.EncodeToString(hxres[16:]),
			"autn":      hex.EncodeToString(autn),
		},
		"_links": map[string]any{"5g-aka": map[string]string{"href": link + "/5g-aka-confirmation"}},
	})
}

// akaConfirmation completes a 5G-AKA authentication with the RES* of the UE
// (Nausf_UEAuthentication_Authenticate, confirmation).
func (h *homeNetwork) akaConfirmation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResStar string `json:"resStar"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT")
		return
	}
	h.mu.Lock()
	auth := h.auths[r.PathValue("id")]
	delete(h.auths, r.PathValue("id"))
	h.mu.Unlock()
	if auth == nil {
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND")
		return
	}
	resStar, err := hex.DecodeString(req.ResStar)
	if err != nil || !bytes.Equal(resStar, auth.xresStar) {
		log.Warn("[SEPP] Authentication of ", auth.supi, " failed")
		reply(w, http.StatusOK, map[string]any{"authResult": "AUTHENTICATION_FAILURE", "supi": auth.supi})
		return
	}
	log.Info("[SEPP] Authentication of ", auth.supi, " succeeded")
	reply(w, http.StatusOK, map[string]any{
		"authResult": "AUTHENTICATION_SUCCESS",
		"supi":       auth.supi,
		"kseaf":      hex.EncodeToString(auth.kseaf),
	})
}

// register stores a registration, and replies with 201 for a new one, 200 for a replaced one.
func register(w http.ResponseWriter, r *http.Request, store map[string]json.RawMessage, key string, mu *sync.Mutex) bool {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT")
		return false
	}
	mu.Lock()
	_, replaced := store[key]
	store[key] = body
	mu.Unlock()
	status := http.StatusCreated
	if replaced {
		status = http.StatusOK
	} else {
		w.Header().Set("Location", apiRoot(r)+r.URL.Path)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
	return true
}

// amfRegistration registers the AMF that serves a UE (Nudm_UECM_Registration).
func (h *homeNetwork) amfRegistration(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	if !h.isSubscriber(supi) {
		problem(w, http.StatusNotFound, "USER_NOT_FOUND")
		return
	}
	if register(w, r, h.amfRegs, supi, &h.mu) {
		log.Info("[SEPP] ", supi, " registered in a visited network")
		if h.onUeAmf != nil {
			h.onUeAmf(supi)
		}
	}
}

// amfModification modifies the registration of the AMF of a UE (Nudm_UECM_Update): with the
// purge flag, the UE is no longer registered with the AMF.
func (h *homeNetwork) amfModification(w http.ResponseWriter, r *http.Request) {
	var modification struct {
		PurgeFlag bool `json:"purgeFlag"`
	}
	json.NewDecoder(r.Body).Decode(&modification)
	if modification.PurgeFlag {
		h.mu.Lock()
		delete(h.amfRegs, r.PathValue("supi"))
		h.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// noContent acknowledges a request without effect in the home network, e.g., the deletion of the
// result of an authentication (Nausf_UEAuthentication_Deregister).
func (h *homeNetwork) noContent(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// smfRegistration registers the SMF of a PDU session of a UE (Nudm_UECM_Registration).
func (h *homeNetwork) smfRegistration(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	if !h.isSubscriber(supi) {
		problem(w, http.StatusNotFound, "USER_NOT_FOUND")
		return
	}
	register(w, r, h.smfRegs, supi+"/"+r.PathValue("id"), &h.mu)
}

// smfDeregistration deregisters the SMF of a PDU session (Nudm_UECM_Deregistration).
func (h *homeNetwork) smfDeregistration(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	delete(h.smfRegs, r.PathValue("supi")+"/"+r.PathValue("id"))
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// snssai returns the S-NSSAI of the UEs.
func (h *homeNetwork) snssai() map[string]any {
	snssai := map[string]any{"sst": h.bridge.cfg.Sst}
	if h.bridge.cfg.Sd != "" {
		snssai["sd"] = h.bridge.cfg.Sd
	}
	return snssai
}

// subscriptionData returns a data set of the subscription of a UE (Nudm_SDM_Get).
func (h *homeNetwork) subscriptionData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	if !h.isSubscriber(supi) {
		problem(w, http.StatusNotFound, "USER_NOT_FOUND")
		return
	}
	ambr := map[string]string{"uplink": h.cfg.Ambr, "downlink": h.cfg.Ambr}
	dnn := h.bridge.cfg.Dnn
	snssaiKey := strconv.Itoa(h.bridge.cfg.Sst)
	if h.bridge.cfg.Sd != "" {
		snssaiKey += "-" + h.bridge.cfg.Sd
	}
	switch r.PathValue("dataset") {
	case "am-data":
		reply(w, http.StatusOK, map[string]any{
			"subscribedUeAmbr": ambr,
			"nssai":            map[string]any{"defaultSingleNssais": []any{h.snssai()}},
		})
	case "smf-select-data":
		reply(w, http.StatusOK, map[string]any{
			"subscribedSnssaiInfos": map[string]any{snssaiKey: map[string]any{
				"dnnInfos": []any{map[string]any{
					"dnn": dnn, "defaultDnnIndicator": true, "lboRoamingAllowed": true,
				}},
			}},
		})
	case "ue-context-in-smf-data":
		reply(w, http.StatusOK, map[string]any{})
	case "sm-data":
		reply(w, http.StatusOK, []any{map[string]any{
			"singleNssai": h.snssai(),
			"dnnConfigurations": map[string]any{dnn: map[string]any{
				"pduSessionTypes": map[string]any{
					"defaultSessionType":  "IPV4",
					"allowedSessionTypes": []string{"IPV4", "IPV6", "IPV4V6"},
				},
				"sscModes": map[string]any{
					"defaultSscMode":  "SSC_MODE_1",
					"allowedSscModes": []string{"SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"},
				},
				"5gQosProfile": map[string]any{
					"5qi": h.cfg.FiveQi,
					"arp": map[string]any{
						"priorityLevel": 8, "preemptCap": "NOT_PREEMPT", "preemptVuln": "PREEMPTABLE",
					},
					"priorityLevel": 8,
				},
				"sessionAmbr": ambr,
			}},
		}})
	default:
		log.Warn("[SEPP] Unsupported subscription data ", r.PathValue("dataset"))
		problem(w, http.StatusNotFound, "DATA_NOT_FOUND")
	}
}

// sdmSubscribe subscribes to the changes of the subscription data of a UE
// (Nudm_SDM_Subscribe); the data never changes.
func (h *homeNetwork) sdmSubscribe(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT")
		return
	}
	h.mu.Lock()
	h.nextId++
	id := strconv.Itoa(h.nextId)
	h.sdmSubs[id] = r.PathValue("supi")
	h.mu.Unlock()
	w.Header().Set("Location", apiRoot(r)+r.URL.Path+"/"+id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(body)
}

// sdmUnsubscribe removes a subscription to the changes of the subscription data
// (Nudm_SDM_Unsubscribe).
func (h *homeNetwork) sdmUnsubscribe(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	delete(h.sdmSubs, r.PathValue("id"))
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

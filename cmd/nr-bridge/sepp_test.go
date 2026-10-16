package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
)

// newTestHome returns the home network of a bridge with the subscribers of the Open5GS setup.
func newTestHome() *homeNetwork {
	b := &Bridge{cfg: Config{
		Subscriber: Subscriber{
			Key: "00112233445566778899AABBCCDDEEFF",
			Opc: "63BFA50EE6523365FF14C1F45F88737D",
			Amf: "8000",
			Sqn: "00000000",
		},
		Dnn: "internet",
		Sst: 1,
	}}
	return &homeNetwork{
		bridge:  b,
		cfg:     SeppConfig{Fqdn: "sepp.test", Plmns: []PlmnId{{"002", "02"}}, FiveQi: 9, Ambr: "1 Gbps"},
		sqn:     make(map[string]uint64),
		auths:   make(map[string]*authContext),
		amfRegs: make(map[string]json.RawMessage),
		smfRegs: make(map[string]json.RawMessage),
		sdmSubs: make(map[string]string),
	}
}

func TestSupiOf(t *testing.T) {
	for in, want := range map[string]string{
		"suci-0-002-02-0000-0-0-0000000003": "imsi-002020000000003",
		"imsi-002020000000003":              "imsi-002020000000003",
	} {
		if got, err := supiOf(in); err != nil || got != want {
			t.Errorf("supiOf(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := supiOf("suci-0-002-02-0000-1-1-abcdef"); err == nil {
		t.Error("SUCI with a protection scheme accepted")
	}
}

func TestExchangeCapability(t *testing.T) {
	h := newTestHome()
	req := httptest.NewRequest("POST", "/n32c-handshake/v1/exchange-capability",
		strings.NewReader(`{"sender":"sepp2","supportedSecCapabilityList":["TLS"],"plmnIdList":[{"mcc":"001","mnc":"01"}]}`))
	rec := httptest.NewRecorder()
	h.exchangeCapability(rec, req)
	var rsp struct {
		Sender                string   `json:"sender"`
		SelectedSecCapability string   `json:"selectedSecCapability"`
		PlmnIdList            []PlmnId `json:"plmnIdList"`
	}
	json.Unmarshal(rec.Body.Bytes(), &rsp)
	if rec.Code != 200 || rsp.Sender != "sepp.test" || rsp.SelectedSecCapability != "TLS" ||
		len(rsp.PlmnIdList) != 1 || rsp.PlmnIdList[0] != (PlmnId{"002", "02"}) {
		t.Errorf("wrong handshake response %d %s", rec.Code, rec.Body.String())
	}
}

// TestFiveGAka runs a 5G-AKA authentication against the computations of the UE (TS 33.501).
func TestFiveGAka(t *testing.T) {
	h := newTestHome()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /nausf-auth/v1/ue-authentications", h.ueAuthentication)
	mux.HandleFunc("PUT /nausf-auth/v1/ue-authentications/{id}/5g-aka-confirmation", h.akaConfirmation)
	sn := "5G:mnc001.mcc001.3gppnetwork.org"

	req := httptest.NewRequest("POST", "/nausf-auth/v1/ue-authentications",
		strings.NewReader(`{"supiOrSuci":"suci-0-002-02-0000-0-0-0000000003","servingNetworkName":"`+sn+`"}`))
	req.Header.Set("3gpp-Sbi-Target-apiRoot", "http://ausf.example")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("authentication: status %d %s", rec.Code, rec.Body.String())
	}
	var ctx struct {
		AuthData struct {
			Rand      string `json:"rand"`
			HxresStar string `json:"hxresStar"`
			Autn      string `json:"autn"`
		} `json:"5gAuthData"`
		Links map[string]map[string]string `json:"_links"`
	}
	json.Unmarshal(rec.Body.Bytes(), &ctx)
	link := ctx.Links["5g-aka"]["href"]
	if !strings.HasPrefix(link, "http://ausf.example/nausf-auth/v1/ue-authentications/") {
		t.Fatalf("wrong link %q", link)
	}

	// the UE: SQN, RES* and KSEAF from its credentials
	opc, _ := hex.DecodeString(h.bridge.cfg.Subscriber.Opc)
	k, _ := hex.DecodeString(h.bridge.cfg.Subscriber.Key)
	randBytes, _ := hex.DecodeString(ctx.AuthData.Rand)
	autn, _ := hex.DecodeString(ctx.AuthData.Autn)
	sqn, ak, ik, ck, res, err := milenage.GenerateKeysWithAUTN(opc, k, randBytes, autn)
	if err != nil {
		t.Fatalf("AUTN rejected by the UE: %v", err)
	}
	if !bytes.Equal(sqn, []byte{0, 0, 0, 0, 0, 1}) {
		t.Errorf("wrong SQN %x", sqn)
	}
	key := append(append([]byte{}, ck...), ik...)
	snb := []byte(sn)
	resStarKdf, _ := ueauth.GetKDFValue(key, ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION, snb,
		ueauth.KDFLen(snb), randBytes, ueauth.KDFLen(randBytes), res, ueauth.KDFLen(res))
	resStar := resStarKdf[16:]
	hres := sha256.Sum256(append(append([]byte{}, randBytes...), resStar...))
	if hex.EncodeToString(hres[16:]) != ctx.AuthData.HxresStar {
		t.Errorf("HXRES* does not match the RES* of the UE")
	}
	sqnXorAk := make([]byte, 6)
	for i := range sqnXorAk {
		sqnXorAk[i] = sqn[i] ^ ak[i]
	}
	kausf, _ := ueauth.GetKDFValue(key, ueauth.FC_FOR_KAUSF_DERIVATION, snb, ueauth.KDFLen(snb),
		sqnXorAk, ueauth.KDFLen(sqnXorAk))
	kseaf, _ := ueauth.GetKDFValue(kausf, ueauth.FC_FOR_KSEAF_DERIVATION, snb, ueauth.KDFLen(snb))

	path := strings.TrimPrefix(link, "http://ausf.example")
	req = httptest.NewRequest("PUT", path,
		strings.NewReader(`{"resStar":"`+hex.EncodeToString(resStar)+`"}`))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var confirmation struct {
		AuthResult string `json:"authResult"`
		Supi       string `json:"supi"`
		Kseaf      string `json:"kseaf"`
	}
	json.Unmarshal(rec.Body.Bytes(), &confirmation)
	if confirmation.AuthResult != "AUTHENTICATION_SUCCESS" ||
		confirmation.Supi != "imsi-002020000000003" ||
		confirmation.Kseaf != hex.EncodeToString(kseaf) {
		t.Errorf("wrong confirmation %s", rec.Body.String())
	}

	// a wrong RES* fails, and a second authentication has a greater SQN
	req = httptest.NewRequest("POST", "/nausf-auth/v1/ue-authentications",
		strings.NewReader(`{"supiOrSuci":"imsi-002020000000003","servingNetworkName":"`+sn+`"}`))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &ctx)
	randBytes, _ = hex.DecodeString(ctx.AuthData.Rand)
	autn, _ = hex.DecodeString(ctx.AuthData.Autn)
	sqn, _, _, _, _, _ = milenage.GenerateKeysWithAUTN(opc, k, randBytes, autn)
	if !bytes.Equal(sqn, []byte{0, 0, 0, 0, 0, 2}) {
		t.Errorf("SQN not incremented: %x", sqn)
	}
	req = httptest.NewRequest("PUT", strings.TrimPrefix(ctx.Links["5g-aka"]["href"], "http://ausf.example"),
		strings.NewReader(`{"resStar":"00000000000000000000000000000000"}`))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &confirmation)
	if confirmation.AuthResult != "AUTHENTICATION_FAILURE" {
		t.Errorf("wrong RES* accepted: %s", rec.Body.String())
	}
}

// TestRegistrations registers the AMF of a UE, purges it, and deletes the authentication result.
func TestRegistrations(t *testing.T) {
	h := newTestHome()
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", h.amfRegistration)
	mux.HandleFunc("PATCH /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", h.amfModification)
	mux.HandleFunc("DELETE /nausf-auth/v1/ue-authentications/{id}/5g-aka-confirmation", h.noContent)
	registered := ""
	h.onUeAmf = func(supi string) { registered = supi }
	path := "/nudm-uecm/v1/imsi-002020000000003/registrations/amf-3gpp-access"
	for _, status := range []int{http.StatusCreated, http.StatusOK} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("PUT", path,
			strings.NewReader(`{"deregCallbackUri":"http://amf/cb","guami":{"plmnId":{"mcc":"001","mnc":"01"}}}`)))
		if rec.Code != status {
			t.Errorf("registration: status %d, want %d", rec.Code, status)
		}
	}
	if registered != "imsi-002020000000003" {
		t.Errorf("registration not reported: %q", registered)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("PATCH", path, strings.NewReader(`{"purgeFlag":true}`)))
	if rec.Code != http.StatusNoContent || len(h.amfRegs) != 0 {
		t.Errorf("purge: status %d, %d registrations left", rec.Code, len(h.amfRegs))
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/nausf-auth/v1/ue-authentications/1/5g-aka-confirmation", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("deletion of the authentication result: status %d", rec.Code)
	}
}

func TestUnknownUe(t *testing.T) {
	h := newTestHome()
	req := httptest.NewRequest("POST", "/nausf-auth/v1/ue-authentications",
		strings.NewReader(`{"supiOrSuci":"imsi-999700000000003","servingNetworkName":"5G:x"}`))
	rec := httptest.NewRecorder()
	h.ueAuthentication(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("UE of another network accepted: %d", rec.Code)
	}
}

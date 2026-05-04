package wgmgr_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wesdod/mira-vpn/mira-vpn-wgmgr/internal/wgmgr"
)

func TestMockProvisioner_CreateDeleteRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p, err := wgmgr.NewMockProvisioner(dir, "10.0.0.1:51820", wgmgr.DefaultMockServerPublicKey, "", "0.0.0.0/0,::/0", 0)
	if err != nil {
		t.Fatal(err)
	}

	meta, err := p.CreatePeer("user-1", "finland")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Location != "Finland" {
		t.Fatalf("expected canonical location Finland, got %q", meta.Location)
	}
	if meta.PeerID == "" || meta.PublicKey == "" {
		t.Fatalf("missing peer fields: %+v", meta)
	}
	confPath := filepath.Join(dir, meta.PeerID+".conf")
	raw, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "[Interface]") || !strings.Contains(s, "[Peer]") {
		t.Fatalf("unexpected config: %s", s)
	}
	if !strings.Contains(s, "Endpoint = 10.0.0.1:51820") {
		t.Fatalf("expected endpoint in config: %s", s)
	}

	if err := p.DeletePeer(meta.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Fatalf("expected conf removed: %v", err)
	}
	if err := p.DeletePeer(meta.PeerID); err != wgmgr.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestHandler_POST_v1_peers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p, err := wgmgr.NewMockProvisioner(dir, "127.0.0.1:51820", wgmgr.DefaultMockServerPublicKey, "", "0.0.0.0/0,::/0", 0)
	if err != nil {
		t.Fatal(err)
	}
	h := wgmgr.NewHandler(p)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/peers", strings.NewReader(`{"userId":"u1","location":"Finland"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		PeerID    string `json:"peerId"`
		PublicKey string `json:"publicKey"`
		Address   string `json:"address"`
		Config    string `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.PeerID == "" || out.PublicKey == "" || out.Address == "" || out.Config == "" {
		t.Fatalf("response: %+v", out)
	}

	delReq, err := http.NewRequest(http.MethodDelete, srv.URL+"/v1/peers/"+out.PeerID, nil)
	if err != nil {
		t.Fatal(err)
	}
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(delResp.Body)
		t.Fatalf("delete status %d: %s", delResp.StatusCode, b)
	}
}

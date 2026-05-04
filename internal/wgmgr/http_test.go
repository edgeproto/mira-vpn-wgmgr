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

	"github.com/edgeproto/mira-vpn-wgmgr/internal/wgmgr"
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

func TestAdminAuthHandler_peerRoutesRequireToken(t *testing.T) {
	t.Parallel()

	const secret = "edge-test-token-please-rotate"
	dir := t.TempDir()
	p, err := wgmgr.NewMockProvisioner(dir, "127.0.0.1:51820", wgmgr.DefaultMockServerPublicKey, "", "0.0.0.0/0,::/0", 0)
	if err != nil {
		t.Fatal(err)
	}
	h := wgmgr.NewHandler(p)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(wgmgr.AdminAuthHandler(secret, mux))
	t.Cleanup(srv.Close)

	t.Run("health without auth", func(t *testing.T) {
		t.Parallel()
		resp, err := http.Get(srv.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health: %d", resp.StatusCode)
		}
	})

	t.Run("POST peers without auth", func(t *testing.T) {
		t.Parallel()
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
		if resp.StatusCode != http.StatusUnauthorized {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("want 401, got %d: %s", resp.StatusCode, b)
		}
	})

	t.Run("POST peers with Bearer", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/peers", strings.NewReader(`{"userId":"u1","location":"Finland"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("want 201, got %d: %s", resp.StatusCode, b)
		}
	})

	t.Run("POST peers with X-Mira-Token", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/peers", strings.NewReader(`{"userId":"u2","location":"Finland"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Mira-Token", secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("want 201, got %d: %s", resp.StatusCode, b)
		}
	})

	t.Run("DELETE peer without auth after create", func(t *testing.T) {
		t.Parallel()
		createReq, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/peers", strings.NewReader(`{"userId":"u3","location":"Finland"}`))
		if err != nil {
			t.Fatal(err)
		}
		createReq.Header.Set("Content-Type", "application/json")
		createReq.Header.Set("Authorization", "Bearer "+secret)
		cr, err := http.DefaultClient.Do(createReq)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			PeerID string `json:"peerId"`
		}
		if err := json.NewDecoder(cr.Body).Decode(&out); err != nil {
			cr.Body.Close()
			t.Fatal(err)
		}
		cr.Body.Close()
		if out.PeerID == "" {
			t.Fatal("empty peer id")
		}

		delReq, err := http.NewRequest(http.MethodDelete, srv.URL+"/v1/peers/"+out.PeerID, nil)
		if err != nil {
			t.Fatal(err)
		}
		dr, err := http.DefaultClient.Do(delReq)
		if err != nil {
			t.Fatal(err)
		}
		defer dr.Body.Close()
		if dr.StatusCode != http.StatusUnauthorized {
			b, _ := io.ReadAll(dr.Body)
			t.Fatalf("want 401, got %d: %s", dr.StatusCode, b)
		}
	})
}

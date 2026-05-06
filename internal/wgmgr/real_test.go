package wgmgr

import (
	"testing"

	"github.com/wesdod/mira-vpn/mira-vpn-wgmgr/pkg/locationregistry"
)

func TestIsSafeInterfaceName(t *testing.T) {
	t.Parallel()

	valid := []string{"wg0", "wg_fin", "wg-prod-1"}
	for _, v := range valid {
		if !isSafeInterfaceName(v) {
			t.Fatalf("expected %q to be valid", v)
		}
	}

	invalid := []string{"", "wg0;rm -rf", "wg fin", "wg@", "this-interface-name-is-too-long"}
	for _, v := range invalid {
		if isSafeInterfaceName(v) {
			t.Fatalf("expected %q to be invalid", v)
		}
	}
}

func TestRealProvisioner_CreatePeer_IdempotentByUserLocation(t *testing.T) {
	t.Parallel()

	cfg := Config{
		RealOutputDir:    t.TempDir(),
		RealInterface:    "wg0",
		RealEndpoint:     "127.0.0.1:51820",
		RealServerPubKey: DefaultMockServerPublicKey,
		RealAllowedIPs:   locationregistry.DefaultAllowedIPs,
		RealDryRun:       true,
		RealCommandTTL:   2,
	}
	r, err := NewRealProvisioner(cfg)
	if err != nil {
		t.Fatal(err)
	}

	first, err := r.CreatePeer("user-1", "finland")
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.CreatePeer("user-1", locationregistry.LocationFinland)
	if err != nil {
		t.Fatal(err)
	}
	if first.PeerID != second.PeerID {
		t.Fatalf("expected idempotent peer id, got %q and %q", first.PeerID, second.PeerID)
	}
	if first.Location != locationregistry.LocationFinland {
		t.Fatalf("expected canonical location %q, got %q", locationregistry.LocationFinland, first.Location)
	}
}

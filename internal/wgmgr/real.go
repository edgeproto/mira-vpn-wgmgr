package wgmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/edgeproto/mira-vpn-wgmgr/pkg/locationregistry"
)

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RealProvisioner writes artifacts and optionally configures a live wg interface.
type RealProvisioner struct {
	*MockProvisioner

	wgInterface    string
	dryRun         bool
	commandTimeout time.Duration
	runner         commandRunner
}

// NewRealProvisioner builds a real-mode provisioner backed by disk + wg set.
func NewRealProvisioner(cfg Config) (*RealProvisioner, error) {
	if !isSafeInterfaceName(cfg.RealInterface) {
		return nil, errors.New("wgmgr: invalid WGMGR_REAL_INTERFACE")
	}
	if strings.TrimSpace(cfg.RealOutputDir) == "" {
		return nil, errors.New("wgmgr: WGMGR_REAL_OUTPUT_DIR is empty")
	}
	mock, err := NewMockProvisioner(
		cfg.RealOutputDir,
		cfg.RealEndpoint,
		cfg.RealServerPubKey,
		cfg.RealDNS,
		cfg.RealAllowedIPs,
		cfg.ClientMTU,
	)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(cfg.RealCommandTTL) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &RealProvisioner{
		MockProvisioner: mock,
		wgInterface:     cfg.RealInterface,
		dryRun:          cfg.RealDryRun,
		commandTimeout:  ttl,
		runner:          execRunner{},
	}, nil
}

func (r *RealProvisioner) CreatePeer(userID, location string) (*PeerMeta, error) {
	if strings.TrimSpace(location) == "" {
		location = locationregistry.DefaultLocationName()
	}
	profile, ok := locationregistry.ProfileForLocation(location)
	if !ok {
		return nil, ErrUnsupportedLocation
	}
	location = profile.Name
	existing, err := r.findExisting(userID, location)
	if err == nil {
		// Peer artifacts survive restarts, but `wg set` peers are ephemeral until
		// persisted via wg-quick or similar. Re-apply so wg0 always matches disk.
		if err := r.applyPeer(existing); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	meta, err := r.MockProvisioner.CreatePeer(userID, location)
	if err != nil {
		return nil, err
	}
	if err := r.applyPeer(meta); err != nil {
		_ = r.MockProvisioner.DeletePeer(meta.PeerID)
		return nil, err
	}
	return meta, nil
}

func (r *RealProvisioner) DeletePeer(peerID string) error {
	metaPath := filepath.Join(r.outputDir, peerID+".json")
	raw, err := os.ReadFile(metaPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil {
		var meta PeerMeta
		if json.Unmarshal(raw, &meta) == nil && meta.PublicKey != "" {
			if rmErr := r.removePeer(meta.PublicKey); rmErr != nil {
				return rmErr
			}
		}
	}
	return r.MockProvisioner.DeletePeer(peerID)
}

func (r *RealProvisioner) applyPeer(meta *PeerMeta) error {
	if meta == nil {
		return errors.New("wgmgr: peer meta is nil")
	}
	args := []string{"set", r.wgInterface, "peer", meta.PublicKey, "allowed-ips", meta.Address}
	if r.dryRun {
		log.Printf("wgmgr dry-run: wg %s", strings.Join(args, " "))
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.commandTimeout)
	defer cancel()
	return r.runner.Run(ctx, "wg", args...)
}

func (r *RealProvisioner) removePeer(publicKey string) error {
	args := []string{"set", r.wgInterface, "peer", publicKey, "remove"}
	if r.dryRun {
		log.Printf("wgmgr dry-run: wg %s", strings.Join(args, " "))
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.commandTimeout)
	defer cancel()
	return r.runner.Run(ctx, "wg", args...)
}

func (r *RealProvisioner) findExisting(userID, location string) (*PeerMeta, error) {
	entries, err := os.ReadDir(r.outputDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(r.outputDir, e.Name()))
		if err != nil {
			continue
		}
		var meta PeerMeta
		if json.Unmarshal(raw, &meta) != nil {
			continue
		}
		if meta.UserID == userID && strings.EqualFold(strings.TrimSpace(meta.Location), strings.TrimSpace(location)) {
			return &meta, nil
		}
	}
	return nil, ErrNotFound
}

func isSafeInterfaceName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

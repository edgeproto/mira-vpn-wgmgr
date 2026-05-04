package wgmgr

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/edgeproto/mira-vpn-wgmgr/pkg/locationregistry"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ErrNotFound is returned when a peer artifact does not exist on disk.
var ErrNotFound = errors.New("wgmgr: peer not found")

// ErrUnsupportedLocation is returned when the location is not in the registry.
var ErrUnsupportedLocation = errors.New("wgmgr: unsupported location")

// PeerMeta is persisted next to the mock client config ({peerID}.json).
type PeerMeta struct {
	PeerID     string `json:"peerId"`
	UserID     string `json:"userId"`
	Location   string `json:"location"`
	PublicKey  string `json:"publicKey"`
	Address    string `json:"address"`
	Config     string `json:"config"`
	ConfigPath string `json:"configPath"`
}

// MockProvisioner writes WireGuard client configs and metadata without calling wg.
type MockProvisioner struct {
	outputDir    string
	endpoint     string
	serverPubKey string
	dns          string
	allowedIPs   string
	clientMTU    int

	mu sync.Mutex
}

// NewMockProvisioner creates a mock provisioner. outputDir is created if missing.
// clientMTU is emitted in client configs when > 0 (see WGMGR_CLIENT_MTU).
func NewMockProvisioner(outputDir, endpoint, serverPubKey, dns, allowedIPs string, clientMTU int) (*MockProvisioner, error) {
	if outputDir == "" {
		return nil, errors.New("wgmgr: mock output dir is empty")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}
	spk, err := wgtypes.ParseKey(serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("wgmgr: parse server public key: %w", err)
	}
	_ = spk // validated
	return &MockProvisioner{
		outputDir:    outputDir,
		endpoint:     endpoint,
		serverPubKey: serverPubKey,
		dns:          dns,
		allowedIPs:   allowedIPs,
		clientMTU:    clientMTU,
	}, nil
}

// CreatePeer generates keys, assigns a /32 inside 10.200.0.0/24, writes .conf + .json.
func (m *MockProvisioner) CreatePeer(userID, location string) (*PeerMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(location) == "" {
		location = locationregistry.DefaultLocationName()
	}
	profile, ok := locationregistry.ProfileForLocation(location)
	if !ok {
		return nil, ErrUnsupportedLocation
	}
	location = profile.Name

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey()

	peerID, err := randomPeerID()
	if err != nil {
		return nil, err
	}

	addr, err := m.nextPeerAddress()
	if err != nil {
		return nil, err
	}

	confName := peerID + ".conf"
	metaName := peerID + ".json"
	confPath := filepath.Join(m.outputDir, confName)

	cfg := locationregistry.BuildClientConfig(locationregistry.ClientConfigInput{
		ClientPrivateKey: priv.String(),
		ClientAddress:    addr,
		DNS:              firstNonEmpty(profile.DNS, m.dns),
		MTU:              m.clientMTU,
		ServerPublicKey:  firstNonEmpty(profile.ServerPublicKey, m.serverPubKey),
		Endpoint:         firstNonEmpty(profile.Endpoint, m.endpoint),
		AllowedIPs:       firstNonEmpty(profile.AllowedIPs, m.allowedIPs),
		Keepalive:        profile.Keepalive,
	})
	if err := os.WriteFile(confPath, []byte(cfg), 0o600); err != nil {
		return nil, err
	}

	meta := &PeerMeta{
		PeerID:     peerID,
		UserID:     userID,
		Location:   location,
		PublicKey:  pub.String(),
		Address:    addr,
		Config:     cfg,
		ConfigPath: confPath,
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		_ = os.Remove(confPath)
		return nil, err
	}
	metaPath := filepath.Join(m.outputDir, metaName)
	if err := os.WriteFile(metaPath, raw, 0o600); err != nil {
		_ = os.Remove(confPath)
		return nil, err
	}

	return meta, nil
}

// DeletePeer removes mock artifacts for peerID.
func (m *MockProvisioner) DeletePeer(peerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if peerID == "" {
		return ErrNotFound
	}
	conf := filepath.Join(m.outputDir, peerID+".conf")
	meta := filepath.Join(m.outputDir, peerID+".json")

	_, errConf := os.Stat(conf)
	_, errMeta := os.Stat(meta)
	if errConf != nil && errMeta != nil {
		if errors.Is(errConf, fs.ErrNotExist) && errors.Is(errMeta, fs.ErrNotExist) {
			return ErrNotFound
		}
		if !errors.Is(errConf, fs.ErrNotExist) {
			return errConf
		}
		return errMeta
	}

	var firstErr error
	if err := os.Remove(conf); err != nil && !errors.Is(err, fs.ErrNotExist) {
		firstErr = err
	}
	if err := os.Remove(meta); err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (m *MockProvisioner) nextPeerAddress() (string, error) {
	entries, err := os.ReadDir(m.outputDir)
	if err != nil {
		return "", err
	}
	maxHost := 1
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.outputDir, e.Name()))
		if err != nil {
			continue
		}
		var meta PeerMeta
		if json.Unmarshal(raw, &meta) != nil {
			continue
		}
		host, ok := lastOctet(meta.Address)
		if ok && host > maxHost {
			maxHost = host
		}
	}
	if maxHost >= 254 {
		return "", errors.New("wgmgr: mock subnet exhausted")
	}
	return fmt.Sprintf("10.200.0.%d/32", maxHost+1), nil
}

func lastOctet(cidr string) (int, bool) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, false
	}
	ip = ip.To4()
	if ip == nil {
		return 0, false
	}
	return int(ip[3]), true
}

func randomPeerID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ParsePeerID validates peer IDs from URL paths (hex-only, fixed length).
func ParsePeerID(s string) (string, error) {
	if len(s) != 32 {
		return "", strconv.ErrSyntax
	}
	for _, c := range s {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return "", strconv.ErrSyntax
	}
	return s, nil
}

func firstNonEmpty(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

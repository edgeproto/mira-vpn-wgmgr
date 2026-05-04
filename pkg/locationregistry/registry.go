package locationregistry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// IPv4-only default: many VPN hosts only NAT IPv4; routing ::/0 without v6 NAT
// can stall clients on AAAA-heavy sites. Use WGMGR_*_ALLOWED_IPS when v6 is ready.
const DefaultAllowedIPs = "0.0.0.0/0"

const (
	LocationFinland = "Finland"
)

// LocationProfile contains location-specific WireGuard server settings.
type LocationProfile struct {
	Name            string
	Endpoint        string
	ServerPublicKey string
	DNS             string
	AllowedIPs      string
	Keepalive       int
	// Optional client/UI metadata (never include secrets here).
	DisplayName string
	Country     string
	LatencyHint string
	FlagCode    string
}

var (
	profilesMu sync.RWMutex
	profiles   = defaultLocationProfiles()
)

type profileInput struct {
	Name            string `json:"name"`
	Endpoint        string `json:"endpoint"`
	ServerPublicKey string `json:"serverPublicKey"`
	DNS             string `json:"dns"`
	AllowedIPs      string `json:"allowedIPs"`
	Keepalive       int    `json:"keepalive"`
	DisplayName     string `json:"displayName"`
	Country         string `json:"country"`
	LatencyHint     string `json:"latencyHint"`
	FlagCode        string `json:"flagCode"`
}

// LocationListing is safe to return to VPN clients (no endpoints or server keys).
type LocationListing struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Country     string `json:"country,omitempty"`
	LatencyHint string `json:"latencyHint,omitempty"`
	FlagCode    string `json:"flagCode,omitempty"`
}

// ClientConfigInput contains values required to render a client config.
type ClientConfigInput struct {
	ClientPrivateKey string
	ClientAddress    string
	DNS              string
	// MTU is written under [Interface] when > 0 (helps path-MTU / TLS stalls on some networks).
	MTU             int
	ServerPublicKey string
	Endpoint        string
	AllowedIPs      string
	Keepalive       int
}

// ProfileForLocation returns a normalized profile for a location.
func ProfileForLocation(location string) (LocationProfile, bool) {
	profilesMu.RLock()
	defer profilesMu.RUnlock()

	key := normalizeKey(location)
	profile, ok := profiles[key]
	if !ok {
		return LocationProfile{}, false
	}
	normalized, err := normalizeProfile(profile.Name, profile)
	if err != nil {
		return LocationProfile{}, false
	}
	return normalized, true
}

// ListLocationProfiles returns normalized profiles sorted by canonical name.
func ListLocationProfiles() []LocationProfile {
	profilesMu.RLock()
	defer profilesMu.RUnlock()

	out := make([]LocationProfile, 0, len(profiles))
	for _, p := range profiles {
		normalized, err := normalizeProfile(p.Name, p)
		if err != nil {
			continue
		}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// ListLocationListings returns client-safe rows for the same locations as
// ListLocationProfiles (sorted by name).
func ListLocationListings() []LocationListing {
	list := ListLocationProfiles()
	out := make([]LocationListing, 0, len(list))
	for _, p := range list {
		disp := strings.TrimSpace(p.DisplayName)
		if disp == "" {
			disp = p.Name
		}
		out = append(out, LocationListing{
			Name:        p.Name,
			DisplayName: disp,
			Country:     strings.TrimSpace(p.Country),
			LatencyHint: strings.TrimSpace(p.LatencyHint),
			FlagCode:    strings.TrimSpace(p.FlagCode),
		})
	}
	return out
}

// DefaultLocationName returns the canonical name used when the client omits
// location (first profile when sorted by name). Falls back to Finland if none.
func DefaultLocationName() string {
	list := ListLocationProfiles()
	if len(list) == 0 {
		return LocationFinland
	}
	return list[0].Name
}

// LoadLocationProfilesFromEnv loads profiles from, in order of precedence:
//  1) WGMGR_LOCATION_PROFILES_FILE — path to a JSON file (same array shape as JSON env)
//  2) WGMGR_LOCATION_PROFILES_JSON — inline JSON
//
// If both file and JSON env are unset or empty, resets to the built-in default (Finland).
func LoadLocationProfilesFromEnv() error {
	if path := strings.TrimSpace(os.Getenv("WGMGR_LOCATION_PROFILES_FILE")); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("locationregistry: read WGMGR_LOCATION_PROFILES_FILE: %w", err)
		}
		return LoadLocationProfilesJSON(strings.TrimSpace(string(raw)))
	}
	raw := strings.TrimSpace(os.Getenv("WGMGR_LOCATION_PROFILES_JSON"))
	if raw == "" {
		profilesMu.Lock()
		profiles = defaultLocationProfiles()
		profilesMu.Unlock()
		return nil
	}
	return LoadLocationProfilesJSON(raw)
}

// LoadLocationProfilesJSON replaces active location profiles from JSON.
// JSON shape: [{"name":"Finland","endpoint":"fi.example:443", ...}]
func LoadLocationProfilesJSON(raw string) error {
	next, err := ParseLocationProfilesJSON(raw)
	if err != nil {
		return err
	}
	profilesMu.Lock()
	profiles = next
	profilesMu.Unlock()
	return nil
}

// ParseLocationProfilesJSON parses and normalizes location profiles JSON without
// mutating active runtime profiles.
func ParseLocationProfilesJSON(raw string) (map[string]LocationProfile, error) {
	var decoded []profileInput
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("locationregistry: parse location profiles JSON: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("locationregistry: location profiles list is empty")
	}

	next := make(map[string]LocationProfile, len(decoded))
	for _, in := range decoded {
		p, err := normalizeProfile(in.Name, LocationProfile{
			Name:            in.Name,
			Endpoint:        in.Endpoint,
			ServerPublicKey: in.ServerPublicKey,
			DNS:             in.DNS,
			AllowedIPs:      in.AllowedIPs,
			Keepalive:       in.Keepalive,
			DisplayName:     in.DisplayName,
			Country:         in.Country,
			LatencyHint:     in.LatencyHint,
			FlagCode:        in.FlagCode,
		})
		if err != nil {
			return nil, err
		}
		if err := validateJSONLocationServerFields(p); err != nil {
			return nil, err
		}
		key := normalizeKey(p.Name)
		if _, dup := next[key]; dup {
			return nil, fmt.Errorf("locationregistry: duplicate location name %q", p.Name)
		}
		next[key] = p
	}
	return next, nil
}

func validateJSONLocationServerFields(p LocationProfile) error {
	if p.Endpoint == "" {
		return fmt.Errorf("locationregistry: location %q: endpoint is required", p.Name)
	}
	if p.ServerPublicKey == "" {
		return fmt.Errorf("locationregistry: location %q: serverPublicKey is required", p.Name)
	}
	return nil
}

func defaultLocationProfiles() map[string]LocationProfile {
	p, err := normalizeProfile(LocationFinland, LocationProfile{
		Name:      LocationFinland,
		Keepalive: 25,
	})
	if err != nil {
		panic(err)
	}
	return map[string]LocationProfile{
		normalizeKey(LocationFinland): p,
	}
}

func normalizeKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeProfile(name string, profile LocationProfile) (LocationProfile, error) {
	canonicalName := strings.TrimSpace(name)
	if canonicalName == "" {
		return LocationProfile{}, errors.New("locationregistry: location profile name is required")
	}
	profile.Name = canonicalName
	profile.Endpoint = strings.TrimSpace(profile.Endpoint)
	profile.ServerPublicKey = strings.TrimSpace(profile.ServerPublicKey)
	profile.DNS = strings.TrimSpace(profile.DNS)
	profile.AllowedIPs = strings.TrimSpace(profile.AllowedIPs)
	if profile.AllowedIPs == "" {
		profile.AllowedIPs = DefaultAllowedIPs
	}
	if profile.Keepalive <= 0 {
		profile.Keepalive = 25
	}
	profile.DisplayName = strings.TrimSpace(profile.DisplayName)
	profile.Country = strings.TrimSpace(profile.Country)
	profile.LatencyHint = strings.TrimSpace(profile.LatencyHint)
	profile.FlagCode = strings.TrimSpace(profile.FlagCode)
	return profile, nil
}

// BuildClientConfig renders a WireGuard client config from input fields.
func BuildClientConfig(in ClientConfigInput) string {
	allowedIPs := strings.TrimSpace(in.AllowedIPs)
	if allowedIPs == "" {
		allowedIPs = DefaultAllowedIPs
	}
	keepalive := in.Keepalive
	if keepalive <= 0 {
		keepalive = 25
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(in.ClientPrivateKey)
	b.WriteString("\n")
	b.WriteString("Address = ")
	b.WriteString(in.ClientAddress)
	b.WriteString("\n")
	if in.MTU > 0 {
		b.WriteString("MTU = ")
		b.WriteString(strconv.Itoa(in.MTU))
		b.WriteString("\n")
	}
	if in.DNS != "" {
		b.WriteString("DNS = ")
		b.WriteString(in.DNS)
		b.WriteString("\n")
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = ")
	b.WriteString(in.ServerPublicKey)
	b.WriteString("\n")
	b.WriteString("Endpoint = ")
	b.WriteString(in.Endpoint)
	b.WriteString("\n")
	b.WriteString("AllowedIPs = ")
	b.WriteString(allowedIPs)
	b.WriteString("\n")
	b.WriteString("PersistentKeepalive = ")
	b.WriteString(strconv.Itoa(keepalive))
	b.WriteString("\n")
	return b.String()
}

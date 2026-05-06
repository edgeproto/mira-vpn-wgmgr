package locationregistry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edgeproto/mira-vpn-wgmgr/pkg/locationregistry"
)

func TestBuildClientConfig_GenericTemplateFields(t *testing.T) {
	t.Parallel()

	cfg := locationregistry.BuildClientConfig(locationregistry.ClientConfigInput{
		ClientPrivateKey: "private-key",
		ClientAddress:    "10.200.0.2/32",
		DNS:              "1.1.1.1",
		ServerPublicKey:  "server-public-key",
		Endpoint:         "fi.mira-vpn.example:51820",
		AllowedIPs:       "0.0.0.0/0,::/0",
		Keepalive:        25,
	})

	required := []string{
		"[Interface]",
		"PrivateKey = private-key",
		"Address = 10.200.0.2/32",
		"DNS = 1.1.1.1",
		"[Peer]",
		"PublicKey = server-public-key",
		"Endpoint = fi.mira-vpn.example:51820",
		"AllowedIPs = 0.0.0.0/0,::/0",
		"PersistentKeepalive = 25",
	}
	for _, r := range required {
		if !strings.Contains(cfg, r) {
			t.Fatalf("expected config to contain %q, got:\n%s", r, cfg)
		}
	}
}

func TestBuildClientConfig_MTU(t *testing.T) {
	t.Parallel()

	cfg := locationregistry.BuildClientConfig(locationregistry.ClientConfigInput{
		ClientPrivateKey: "private-key",
		ClientAddress:    "10.200.0.2/32",
		MTU:              1280,
		ServerPublicKey:  "server-public-key",
		Endpoint:         "fi.example:51820",
	})
	if !strings.Contains(cfg, "MTU = 1280") {
		t.Fatalf("expected MTU line, got:\n%s", cfg)
	}
}

func TestBuildClientConfig_DefaultAllowedIPs(t *testing.T) {
	t.Parallel()

	cfg := locationregistry.BuildClientConfig(locationregistry.ClientConfigInput{
		ClientPrivateKey: "private-key",
		ClientAddress:    "10.200.0.2/32",
		ServerPublicKey:  "server-public-key",
		Endpoint:         "fi.mira-vpn.example:51820",
	})

	if !strings.Contains(cfg, "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("expected default allowed IPs, got:\n%s", cfg)
	}
}

func TestProfileForLocation_DefaultFinlandProfile(t *testing.T) {
	t.Parallel()

	profile, ok := locationregistry.ProfileForLocation("finland")
	if !ok {
		t.Fatalf("expected finland profile")
	}
	if profile.Name != locationregistry.LocationFinland {
		t.Fatalf("expected name %q, got %q", locationregistry.LocationFinland, profile.Name)
	}
	if profile.AllowedIPs != locationregistry.DefaultAllowedIPs {
		t.Fatalf("expected default allowed IPs, got %q", profile.AllowedIPs)
	}
	if profile.Keepalive != 25 {
		t.Fatalf("expected keepalive 25, got %d", profile.Keepalive)
	}
}

func TestParseLocationProfilesJSON_NormalizesProfiles(t *testing.T) {
	t.Parallel()

	raw := `[
		{
			"name":"Finland",
			"endpoint":"fi.example.com:443",
			"serverPublicKey":"pub-fi",
			"wgmgrBaseUrl":"  http://fi-wgmgr.example:9090/  ",
			"dns":"1.1.1.1",
			"allowedIPs":"0.0.0.0/0",
			"keepalive":30
		},
		{
			"name":"Germany",
			"endpoint":"de.example.com:443",
			"serverPublicKey":"pub-de",
			"dns":"8.8.8.8"
		}
	]`

	profiles, err := locationregistry.ParseLocationProfilesJSON(raw)
	if err != nil {
		t.Fatalf("ParseLocationProfilesJSON returned error: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
	de, ok := profiles["germany"]
	if !ok {
		t.Fatalf("expected germany profile key")
	}
	if de.AllowedIPs != locationregistry.DefaultAllowedIPs {
		t.Fatalf("expected default allowed IPs, got %q", de.AllowedIPs)
	}
	if de.Keepalive != 25 {
		t.Fatalf("expected default keepalive 25, got %d", de.Keepalive)
	}
	fi, ok := profiles["finland"]
	if !ok {
		t.Fatalf("expected finland profile key")
	}
	if fi.WgmgrBaseURL != "http://fi-wgmgr.example:9090/" {
		t.Fatalf("expected normalized wgmgrBaseUrl, got %q", fi.WgmgrBaseURL)
	}
}

func TestParseLocationProfilesJSON_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	_, err := locationregistry.ParseLocationProfilesJSON(`[{"name":"  "}]`)
	if err == nil {
		t.Fatal("expected error for empty location name")
	}
}

func TestParseLocationProfilesJSON_RejectsMissingEndpoint(t *testing.T) {
	t.Parallel()

	_, err := locationregistry.ParseLocationProfilesJSON(
		`[{"name":"X","serverPublicKey":"abc"}]`,
	)
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestParseLocationProfilesJSON_RejectsMissingServerKey(t *testing.T) {
	t.Parallel()

	_, err := locationregistry.ParseLocationProfilesJSON(
		`[{"name":"X","endpoint":"x:443"}]`,
	)
	if err == nil {
		t.Fatal("expected error for missing serverPublicKey")
	}
}

func TestParseLocationProfilesJSON_RejectsDuplicateNames(t *testing.T) {
	t.Parallel()

	_, err := locationregistry.ParseLocationProfilesJSON(`[
		{"name":"Same","endpoint":"a:1","serverPublicKey":"k1"},
		{"name":"same","endpoint":"b:1","serverPublicKey":"k2"}
	]`)
	if err == nil {
		t.Fatal("expected error for duplicate location name")
	}
}

func TestDefaultLocationName_FirstSortedProfile(t *testing.T) {
	raw := `[
		{"name":"Germany","endpoint":"de.example.com:443","serverPublicKey":"de-pub"},
		{"name":"Finland","endpoint":"fi.example.com:443","serverPublicKey":"fi-pub"}
	]`
	if err := locationregistry.LoadLocationProfilesJSON(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Unsetenv("WGMGR_LOCATION_PROFILES_JSON")
		_ = os.Unsetenv("WGMGR_LOCATION_PROFILES_FILE")
		if err := locationregistry.LoadLocationProfilesFromEnv(); err != nil {
			t.Errorf("cleanup LoadLocationProfilesFromEnv: %v", err)
		}
	})

	if got := locationregistry.DefaultLocationName(); got != "Finland" {
		t.Fatalf("DefaultLocationName: want Finland, got %q", got)
	}
}

func TestLoadLocationProfilesFromEnv_FilePrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	content := `[{"name":"Netherlands","endpoint":"nl:443","serverPublicKey":"k","displayName":"Amsterdam"}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	prevFile, hadFile := os.LookupEnv("WGMGR_LOCATION_PROFILES_FILE")
	prevJSON, hadJSON := os.LookupEnv("WGMGR_LOCATION_PROFILES_JSON")
	t.Cleanup(func() {
		if hadFile {
			_ = os.Setenv("WGMGR_LOCATION_PROFILES_FILE", prevFile)
		} else {
			_ = os.Unsetenv("WGMGR_LOCATION_PROFILES_FILE")
		}
		if hadJSON {
			_ = os.Setenv("WGMGR_LOCATION_PROFILES_JSON", prevJSON)
		} else {
			_ = os.Unsetenv("WGMGR_LOCATION_PROFILES_JSON")
		}
		_ = locationregistry.LoadLocationProfilesFromEnv()
	})
	_ = os.Setenv("WGMGR_LOCATION_PROFILES_FILE", path)
	_ = os.Setenv("WGMGR_LOCATION_PROFILES_JSON", `[{"name":"Wrong","endpoint":"x:1","serverPublicKey":"y"}]`)
	if err := locationregistry.LoadLocationProfilesFromEnv(); err != nil {
		t.Fatal(err)
	}

	list := locationregistry.ListLocationListings()
	if len(list) != 1 || list[0].Name != "Netherlands" || list[0].DisplayName != "Amsterdam" {
		t.Fatalf("unexpected listings: %+v", list)
	}
}

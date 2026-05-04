package wgmgr

import (
	"os"
	"strconv"
)

// Config holds WireGuard management service settings.
//
// Location profiles are loaded separately via
// WGMGR_LOCATION_PROFILES_FILE or WGMGR_LOCATION_PROFILES_JSON
// (see pkg/locationregistry). This struct is only for the WireGuard manager
// daemon (cmd/wgmgr).
//
// Env:
//   - PORT: listen port (default "9090")
//   - WGMGR_MODE: "mock" (default) or "real"
//   - WGMGR_MOCK_OUTPUT_DIR: directory for peer .conf and metadata (default ./var/wgmgr-mock)
//   - WGMGR_MOCK_ENDPOINT: WireGuard server endpoint host:port for client configs
//   - WGMGR_MOCK_SERVER_PUBLIC_KEY: server WireGuard public key (base64)
//   - WGMGR_MOCK_DNS: optional DNS line in [Interface] (e.g. 1.1.1.1)
//   - WGMGR_REAL_OUTPUT_DIR: directory for peer artifacts in real mode (default /etc/wireguard/mira-peers)
//   - WGMGR_REAL_INTERFACE: target WireGuard interface for wg set (default wg0)
//   - WGMGR_REAL_DRY_RUN: if true, log command without executing it
//   - WGMGR_REAL_COMMAND_TIMEOUT_SECONDS: timeout for wg command execution (default 5)
//   - WGMGR_CLIENT_MTU: optional MTU line in client [Interface] (default 1280; set 0 to omit)
type Config struct {
	Port             string
	Mode             string
	ClientMTU        int
	MockOutputDir    string
	MockEndpoint     string
	MockServerPubKey string
	MockDNS          string
	MockAllowedIPs   string
	RealOutputDir    string
	RealInterface    string
	RealEndpoint     string
	RealServerPubKey string
	RealDNS          string
	RealAllowedIPs   string
	RealDryRun       bool
	RealCommandTTL   int
}

func LoadConfigFromEnv() Config {
	return Config{
		Port:             getEnv("PORT", "9090"),
		Mode:             getEnv("WGMGR_MODE", "mock"),
		ClientMTU:        getEnvInt("WGMGR_CLIENT_MTU", 1280),
		MockOutputDir:    getEnv("WGMGR_MOCK_OUTPUT_DIR", "var/wgmgr-mock"),
		MockEndpoint:     getEnv("WGMGR_MOCK_ENDPOINT", "127.0.0.1:51820"),
		MockServerPubKey: getEnv("WGMGR_MOCK_SERVER_PUBLIC_KEY", DefaultMockServerPublicKey),
		MockDNS:          os.Getenv("WGMGR_MOCK_DNS"),
		MockAllowedIPs:   getEnv("WGMGR_MOCK_ALLOWED_IPS", "0.0.0.0/0"),
		RealOutputDir:    getEnv("WGMGR_REAL_OUTPUT_DIR", "/etc/wireguard/mira-peers"),
		RealInterface:    getEnv("WGMGR_REAL_INTERFACE", "wg0"),
		RealEndpoint:     getEnv("WGMGR_REAL_ENDPOINT", getEnv("WGMGR_MOCK_ENDPOINT", "127.0.0.1:51820")),
		RealServerPubKey: getEnv("WGMGR_REAL_SERVER_PUBLIC_KEY", getEnv("WGMGR_MOCK_SERVER_PUBLIC_KEY", DefaultMockServerPublicKey)),
		RealDNS:          getEnv("WGMGR_REAL_DNS", os.Getenv("WGMGR_MOCK_DNS")),
		RealAllowedIPs:   getEnv("WGMGR_REAL_ALLOWED_IPS", getEnv("WGMGR_MOCK_ALLOWED_IPS", "0.0.0.0/0")),
		RealDryRun:       getEnvBool("WGMGR_REAL_DRY_RUN", false),
		RealCommandTTL:   getEnvInt("WGMGR_REAL_COMMAND_TIMEOUT_SECONDS", 5),
	}
}

// DefaultMockServerPublicKey is a valid WireGuard public key used when
// WGMGR_MOCK_SERVER_PUBLIC_KEY is unset (local dev).
const DefaultMockServerPublicKey = "BB/7/1u13mBwC2kWQyEnKcuU1z9MChg3QiJjezAmujo="

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func getEnvBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

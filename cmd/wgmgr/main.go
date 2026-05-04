package main

import (
	"log"
	"net/http"
	"time"

	"github.com/wesdod/mira-vpn/mira-vpn-wgmgr/internal/wgmgr"
	"github.com/wesdod/mira-vpn/mira-vpn-wgmgr/pkg/locationregistry"
)

func main() {
	cfg := wgmgr.LoadConfigFromEnv()
	if err := locationregistry.LoadLocationProfilesFromEnv(); err != nil {
		log.Fatal(err)
	}

	var (
		prov wgmgr.Provisioner
		err  error
	)
	switch cfg.Mode {
	case "mock":
		prov, err = wgmgr.NewMockProvisioner(
			cfg.MockOutputDir,
			cfg.MockEndpoint,
			cfg.MockServerPubKey,
			cfg.MockDNS,
			cfg.MockAllowedIPs,
			cfg.ClientMTU,
		)
	case "real":
		prov, err = wgmgr.NewRealProvisioner(cfg)
	default:
		log.Fatalf("unsupported WGMGR_MODE %q (supported: mock|real)", cfg.Mode)
	}
	if err != nil {
		log.Fatal(err)
	}

	h := wgmgr.NewHandler(prov)
	mux := http.NewServeMux()
	h.Register(mux)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if cfg.Mode == "real" {
		log.Printf("wgmgr (real) listening on %s, interface=%s, output=%s, dryRun=%t", srv.Addr, cfg.RealInterface, cfg.RealOutputDir, cfg.RealDryRun)
	} else {
		log.Printf("wgmgr (mock) listening on %s, output=%s", srv.Addr, cfg.MockOutputDir)
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

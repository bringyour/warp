package main

import (
	"strings"
	"testing"
)

// The LB TLS key-exchange groups, in server preference order. X25519 comes
// first so a modern client's key share is accepted in the first flight: with
// secp384r1 alone, every handshake from a client that offers X25519 costs a
// HelloRetryRequest round trip plus a P-384 ECDH, which on edge-3 managed 809
// ops/s against 25,412 for X25519 and let handshake retries saturate the LB.
// prime256v1 and secp384r1 remain for clients without X25519.
const lbEcdhCurves = "X25519:prime256v1:secp384r1"

// Every generated LB server block negotiates X25519 first, then P-256, then
// P-384, and nothing else. A single P-384-only block would keep forcing the
// HelloRetryRequest path for the clients DNS sends to that block.
func TestNginxConfigPrefersX25519KeyExchange(t *testing.T) {
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}

	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	curveDirectives := 0
	for blockName, config := range nginxConfig.Generate() {
		for _, line := range strings.Split(config, "\n") {
			directive := strings.TrimSpace(line)
			if i := strings.Index(directive, "#"); 0 <= i {
				directive = strings.TrimSpace(directive[:i])
			}
			if !strings.HasPrefix(directive, "ssl_ecdh_curve") {
				continue
			}
			curveDirectives += 1
			if want := "ssl_ecdh_curve " + lbEcdhCurves + ";"; directive != want {
				t.Errorf("block %s: %q, want %q", blockName, directive, want)
			}
		}
	}
	if curveDirectives == 0 {
		t.Fatal("generated LB config has no ssl_ecdh_curve directive")
	}
}

package main

import (
	"strings"
	"testing"
)

// An upstream's own 502 is an application answer in this stack: the API
// returns 502 when a dependency it called refused the work ("The password
// reset code could not be sent", an immutable upload that failed its
// readback). With http_502 and non_idempotent in proxy_next_upstream, nginx
// re-executed those POSTs on a sibling block, so one password reset made two
// codes and two SMS attempts on 2026-10-19. Connection failures and refused
// connects stay covered by error, and a draining API answers 503.
func TestNginxConfigRetriesNoUpstreamApplication502(t *testing.T) {
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	directives := 0
	for blockName, config := range nginxConfig.Generate() {
		for _, line := range strings.Split(config, "\n") {
			fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
			if len(fields) == 0 || fields[0] != "proxy_next_upstream" {
				continue
			}
			directives += 1
			conditions := map[string]bool{}
			for _, condition := range fields[1:] {
				conditions[condition] = true
			}
			if conditions["http_502"] || conditions["http_500"] || conditions["http_504"] {
				t.Errorf("block %s retries an upstream application answer: %q", blockName, line)
			}
			for _, kept := range []string{"error", "timeout", "http_503"} {
				if !conditions[kept] {
					t.Errorf("block %s no longer retries %s over a draining upstream: %q", blockName, kept, line)
				}
			}
		}
	}
	if directives == 0 {
		t.Fatal("generated config has no proxy_next_upstream directive")
	}
}

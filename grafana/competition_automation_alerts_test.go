// Protects routing and privacy for the optional automation control plane.
package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Both rules use the existing competition routing and a valid scheduler grid.
func TestCompetitionAutomationAlertsRouteWithoutCandidateLabels(t *testing.T) {
	body, err := os.ReadFile("alerting/competition-automation.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	config := string(body)
	for _, required := range []string{
		"interval: 20s", "automation_oldest_reward_event_age_seconds",
		"automation_supervisor_heartbeat_age_seconds", "automation_supervisor_expected", "automation_hold_active", "<= 30", "params: [300]",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("missing %q", required)
		}
	}
	if count := strings.Count(config, "labels: {service: sim-latency, severity: warn}"); count != 3 {
		t.Fatalf("routed rules = %d, want 3", count)
	}
	for _, forbidden := range []string{"job_id", "patch_sha256", "raw_score", "normalized_score"} {
		if strings.Contains(config, forbidden) {
			t.Errorf("alert exposes private candidate label %s", forbidden)
		}
	}
}

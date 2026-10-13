package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDataDiskAlertsWarnPageAndFailClosedOnEdge6(t *testing.T) {
	data, err := os.ReadFile("alerting/data-disk.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse data disk alerts: %v", err)
	}
	config := string(data)
	for _, required := range []string{
		`node_filesystem_avail_bytes{mountpoint="/mnt/data"}`,
		`node_filesystem_size_bytes{mountpoint="/mnt/data"} > 0`,
		"params: [0.15], type: lt",
		"params: [0.05], type: lt",
		"severity: warn",
		"severity: page",
		`absent(node_filesystem_avail_bytes{env="main",host="by-us-fmt-5-edge-6",mountpoint="/mnt/data"})`,
		"execErrState: Error",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("data disk alert configuration is missing %q", required)
		}
	}
	if count := strings.Count(config, "\n      - uid: data-disk-"); count != 3 {
		t.Fatalf("data disk alert count = %d, want 3", count)
	}
}

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDataDiskAlertsWarnPageAndFailClosedOnRedisPoolsAndMinioDrives(t *testing.T) {
	data, err := os.ReadFile("alerting/data-disk.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Rules []struct {
				UID  string `yaml:"uid"`
				Data []struct {
					Model struct {
						Expr string `yaml:"expr"`
					} `yaml:"model"`
				} `yaml:"data"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse data disk alerts: %v", err)
	}
	config := string(data)

	// warn and page evaluate each redis pool and each minio drive by itself:
	// minio fails every write once one drive of its erasure set is full
	fraction := `max by (env, host, mountpoint) (node_filesystem_avail_bytes{mountpoint=~"/mnt/data|/mnt/blob[0-9]+"}) / max by (env, host, mountpoint) (node_filesystem_size_bytes{mountpoint=~"/mnt/data|/mnt/blob[0-9]+"} > 0)`
	if count := strings.Count(config, fraction); count != 2 {
		t.Errorf("per disk free fraction query count = %d, want 2", count)
	}
	for _, required := range []string{
		"params: [0.15], type: lt",
		"params: [0.05], type: lt",
		"severity: warn",
		"severity: page",
		"{{ $labels.host }} {{ $labels.mountpoint }} is below 15% free",
		"{{ $labels.host }} {{ $labels.mountpoint }} is below 5% free",
		"execErrState: Error",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("data disk alert configuration is missing %q", required)
		}
	}

	// a disk that stops reporting would silence both rules above, so each one
	// that matters fails closed on its own series
	var telemetry string
	for _, group := range document.Groups {
		for _, rule := range group.Rules {
			if rule.UID == "data-disk-edge-6-telemetry-missing" && len(rule.Data) > 0 {
				telemetry = rule.Data[0].Model.Expr
			}
		}
	}
	disks := []struct{ host, mountpoint string }{
		{"by-us-fmt-5-edge-6", "/mnt/data"},
		{"by-us-fmt-5-edge-5", "/mnt/data"},
		{"by-us-fmt-5-edge-5", "/mnt/blob1"},
		{"by-us-fmt-5-edge-5", "/mnt/blob2"},
		{"by-us-fmt-5-edge-5", "/mnt/blob3"},
		{"by-us-fmt-5-edge-5", "/mnt/blob4"},
	}
	for _, disk := range disks {
		absent := fmt.Sprintf(`absent(node_filesystem_avail_bytes{env="main",host=%q,mountpoint=%q})`, disk.host, disk.mountpoint)
		if !strings.Contains(telemetry, absent) {
			t.Errorf("missing telemetry expr does not fail closed on %s %s", disk.host, disk.mountpoint)
		}
	}
	if count := strings.Count(telemetry, " or absent("); count != len(disks)-1 {
		t.Errorf("missing telemetry expr joins %d absent terms with or, want %d", count, len(disks)-1)
	}
	if !strings.Contains(config, "{{ $labels.host }} has reported no {{ $labels.mountpoint }} free space") {
		t.Errorf("missing telemetry summary does not name the disk")
	}

	if count := strings.Count(config, "\n      - uid: data-disk-"); count != 3 {
		t.Fatalf("data disk alert count = %d, want 3", count)
	}
}

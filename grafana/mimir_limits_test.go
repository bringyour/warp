package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Exercise the operator-facing YAML through the same limits renderer used by
// the child config. Omission must retain Mimir's default; zero explicitly
// disables the limit and must not be confused with an omitted setting.
func TestMimirLimitsConfig(t *testing.T) {
	for _, test := range []struct {
		name          string
		configYAML    string
		wantRetention string
		wantLimit     int
		hasLimit      bool
	}{
		{
			name:          "no mimir settings",
			configYAML:    "{}",
			wantRetention: defaultMimirRetention,
		},
		{
			name:          "empty mimir settings",
			configYAML:    "mimir: {}",
			wantRetention: defaultMimirRetention,
		},
		{
			name:          "retention only preserves series default",
			configYAML:    "mimir:\n  retention: 720h\n",
			wantRetention: "720h",
		},
		{
			name:          "one million cluster series",
			configYAML:    "mimir:\n  max_global_series_per_user: 1000000\n",
			wantRetention: defaultMimirRetention,
			wantLimit:     1000000,
			hasLimit:      true,
		},
		{
			name:          "custom limit and retention",
			configYAML:    "mimir:\n  retention: 720h\n  max_global_series_per_user: 2000000\n",
			wantRetention: "720h",
			wantLimit:     2000000,
			hasLimit:      true,
		},
		{
			name:          "explicit zero disables limit",
			configYAML:    "mimir:\n  max_global_series_per_user: 0\n",
			wantRetention: defaultMimirRetention,
			wantLimit:     0,
			hasLimit:      true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config GrafanaConfig
			if err := yaml.Unmarshal([]byte(test.configYAML), &config); err != nil {
				t.Fatal(err)
			}
			rendered, err := yaml.Marshal(map[string]any{"limits": mimirLimitsConfig(config.Mimir)})
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				Limits map[string]any `yaml:"limits"`
			}
			if err := yaml.Unmarshal(rendered, &parsed); err != nil {
				t.Fatal(err)
			}
			if got := parsed.Limits["compactor_blocks_retention_period"]; got != test.wantRetention {
				t.Fatalf("retention = %v, want %s", got, test.wantRetention)
			}
			limit, present := parsed.Limits["max_global_series_per_user"]
			if present != test.hasLimit {
				t.Fatalf("series limit present = %t, want %t:\n%s", present, test.hasLimit, rendered)
			}
			if test.hasLimit && limit != test.wantLimit {
				t.Fatalf("series limit = %#v, want integer %d", limit, test.wantLimit)
			}
		})
	}
}

func TestMimirLimitsConfigRejectsNegativeSeriesLimit(t *testing.T) {
	var config GrafanaConfig
	if err := yaml.Unmarshal([]byte("mimir:\n  max_global_series_per_user: -1\n"), &config); err != nil {
		t.Fatal(err)
	}
	defer func() {
		got := recover()
		err, ok := got.(error)
		if !ok || err.Error() != "mimir.max_global_series_per_user must be non-negative" {
			t.Fatalf("panic = %v, want negative series limit validation error", got)
		}
	}()
	mimirLimitsConfig(config.Mimir)
}

// renderedIngestionLimits renders an operator grafana.yml through the child
// limits renderer and reads back only the distributor token-bucket fields.
func renderedIngestionLimits(t *testing.T, configYAML string) (rate *float64, burst *int) {
	t.Helper()
	var config GrafanaConfig
	if err := yaml.Unmarshal([]byte(configYAML), &config); err != nil {
		t.Fatal(err)
	}
	rendered, err := yaml.Marshal(map[string]any{"limits": mimirLimitsConfig(config.Mimir)})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Limits struct {
			IngestionRate      *float64 `yaml:"ingestion_rate"`
			IngestionBurstSize *int     `yaml:"ingestion_burst_size"`
		} `yaml:"limits"`
	}
	if err := yaml.Unmarshal(rendered, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.Limits.IngestionRate, parsed.Limits.IngestionBurstSize
}

// Mimir admits ingestion_rate divided by the healthy distributors on each
// distributor, and the fronts route publishers to co-located distributors, so
// the hottest distributor, not the fleet sum, decides discards. On 2026-10-12
// the six-replica fleet attempted about 10300 samples/s against the 10000
// default (1667/s per distributor) while each edge distributor received
// 1800-2000/s and discarded the excess as rate_limited. grafana.yml must be
// able to raise the tenant rate and burst; before this, the renderer dropped
// both settings and every child kept Mimir's default.
func TestMimirLimitsConfigIngestionRate(t *testing.T) {
	for _, test := range []struct {
		name       string
		configYAML string
		wantRate   float64
		hasRate    bool
		wantBurst  int
		hasBurst   bool
	}{
		{
			name:       "omission keeps the mimir defaults",
			configYAML: "mimir:\n  max_global_series_per_user: 2000000\n",
		},
		{
			name:       "rate only keeps the default burst",
			configYAML: "mimir:\n  ingestion_rate: 64000\n",
			wantRate:   64000,
			hasRate:    true,
		},
		{
			name:       "fractional rate",
			configYAML: "mimir:\n  ingestion_rate: 12500.5\n",
			wantRate:   12500.5,
			hasRate:    true,
		},
		{
			// Main's setting from 2026-10-12: 64000/s, a 10667/s share on each of
			// six distributors, with Mimir's default 20 s burst-to-rate proportion
			name:       "rate and burst",
			configYAML: "mimir:\n  max_global_series_per_user: 2000000\n  ingestion_rate: 64000\n  ingestion_burst_size: 1280000\n",
			wantRate:   64000,
			hasRate:    true,
			wantBurst:  1280000,
			hasBurst:   true,
		},
		{
			name:       "burst equal to the rate",
			configYAML: "mimir:\n  ingestion_rate: 64000\n  ingestion_burst_size: 64000\n",
			wantRate:   64000,
			hasRate:    true,
			wantBurst:  64000,
			hasBurst:   true,
		},
		{
			name:       "burst only, above the default rate",
			configYAML: "mimir:\n  ingestion_burst_size: 400000\n",
			wantBurst:  400000,
			hasBurst:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rate, burst := renderedIngestionLimits(t, test.configYAML)
			if (rate != nil) != test.hasRate {
				t.Fatalf("ingestion_rate present = %t, want %t", rate != nil, test.hasRate)
			}
			if test.hasRate && *rate != test.wantRate {
				t.Fatalf("ingestion_rate = %v, want %v", *rate, test.wantRate)
			}
			if (burst != nil) != test.hasBurst {
				t.Fatalf("ingestion_burst_size present = %t, want %t", burst != nil, test.hasBurst)
			}
			if test.hasBurst && *burst != test.wantBurst {
				t.Fatalf("ingestion_burst_size = %d, want %d", *burst, test.wantBurst)
			}
		})
	}
}

// A zero rate admits nothing after the first burst, and a non-finite or
// non-positive value is never a deliberate setting: fail the render instead of
// starting a child that silently drops every push.
func TestMimirLimitsConfigRejectsInvalidIngestionLimits(t *testing.T) {
	for _, test := range []struct {
		name       string
		configYAML string
		wantPanic  string
	}{
		{"zero rate", "mimir:\n  ingestion_rate: 0\n", "mimir.ingestion_rate must be a positive finite number"},
		{"negative rate", "mimir:\n  ingestion_rate: -1\n", "mimir.ingestion_rate must be a positive finite number"},
		{"infinite rate", "mimir:\n  ingestion_rate: .inf\n", "mimir.ingestion_rate must be a positive finite number"},
		{"not a number rate", "mimir:\n  ingestion_rate: .nan\n", "mimir.ingestion_rate must be a positive finite number"},
		{"zero burst", "mimir:\n  ingestion_burst_size: 0\n", "mimir.ingestion_burst_size must be positive"},
		{"negative burst", "mimir:\n  ingestion_burst_size: -5\n", "mimir.ingestion_burst_size must be positive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config GrafanaConfig
			if err := yaml.Unmarshal([]byte(test.configYAML), &config); err != nil {
				t.Fatal(err)
			}
			defer func() {
				got := recover()
				err, ok := got.(error)
				if !ok || err.Error() != test.wantPanic {
					t.Fatalf("panic = %v, want %q", got, test.wantPanic)
				}
			}()
			mimirLimitsConfig(config.Mimir)
		})
	}
}

// Mimir divides ingestion_rate among the healthy distributors but applies
// ingestion_burst_size whole on each, and its burst factor must be at least 1:
// the burst must be at least the tenant rate. Raising only the rate past the
// 200000 default burst, or setting a burst below the rate the children run
// with, used to render a bucket shallower than one second of the tenant rate.
// The children's effective values, defaults included, are what is compared.
func TestMimirLimitsConfigRejectsBurstBelowRate(t *testing.T) {
	for _, test := range []struct {
		name       string
		configYAML string
	}{
		{"burst below the rate", "mimir:\n  ingestion_rate: 64000\n  ingestion_burst_size: 63999\n"},
		{"rate above the default burst", "mimir:\n  ingestion_rate: 200001\n"},
		{"burst below the default rate", "mimir:\n  ingestion_burst_size: 9999\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config GrafanaConfig
			if err := yaml.Unmarshal([]byte(test.configYAML), &config); err != nil {
				t.Fatal(err)
			}
			const wantPanic = "mimir.ingestion_burst_size must be at least mimir.ingestion_rate"
			defer func() {
				got := recover()
				err, ok := got.(error)
				if !ok || err.Error() != wantPanic {
					t.Fatalf("panic = %v, want %q", got, wantPanic)
				}
			}()
			mimirLimitsConfig(config.Mimir)
		})
	}
}

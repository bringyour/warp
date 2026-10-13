package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type pgbouncerAlertRule struct {
	UID         string            `yaml:"uid"`
	NoDataState string            `yaml:"noDataState"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Data        []struct {
		RefID         string `yaml:"refId"`
		DatasourceUID string `yaml:"datasourceUid"`
		Model         struct {
			Expr       string `yaml:"expr"`
			Conditions []struct {
				Evaluator struct {
					Params []float64 `yaml:"params"`
					Type   string    `yaml:"type"`
				} `yaml:"evaluator"`
			} `yaml:"conditions"`
		} `yaml:"model"`
	} `yaml:"data"`
}

func pgbouncerAlertRules(t *testing.T) map[string]pgbouncerAlertRule {
	t.Helper()
	data, err := os.ReadFile("alerting/pgbouncer.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Rules []pgbouncerAlertRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	rules := map[string]pgbouncerAlertRule{}
	for _, group := range document.Groups {
		for _, rule := range group.Rules {
			rules[rule.UID] = rule
		}
	}
	return rules
}

// On 2026-10-12 most of Main's 32 PgBouncer pools held thousands of queued
// clients and no server for minutes, twice, while PostgreSQL stayed up and
// nothing alerted. The starved pool pages from the exporter's own streak.
func TestPgBouncerStarvedPoolPages(t *testing.T) {
	rule, ok := pgbouncerAlertRules(t)["pgbouncer-pool-starved"]
	if !ok {
		t.Fatal("missing PgBouncer starved pool alert")
	}
	if rule.Labels["severity"] != "page" {
		t.Errorf("starved pool alert severity %q, want page", rule.Labels["severity"])
	}
	expr := rule.Data[0].Model.Expr
	if rule.Data[0].DatasourceUID != "warp-mimir" || !strings.Contains(expr, "pgbouncer_pool_starved_seconds") {
		t.Errorf("starved pool alert does not query the exporter's streak: %s", expr)
	}
	if !strings.Contains(expr, "by (env, host, pgbouncer)") {
		t.Errorf("starved pool alert does not name the instance: %s", expr)
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] > 30 {
		t.Errorf("starved pool alert threshold %v %v must fire within 30 s of starvation", evaluator.Type, evaluator.Params)
	}
}

// A missing exporter series blinds the starved pool alert, so its absence
// alerts instead of resolving.
func TestPgBouncerExporterAbsenceAlerts(t *testing.T) {
	rule, ok := pgbouncerAlertRules(t)["pgbouncer-pool-exporter-down"]
	if !ok {
		t.Fatal("missing PgBouncer exporter alert")
	}
	if rule.NoDataState != "Alerting" {
		t.Errorf("exporter alert noDataState %q, want Alerting", rule.NoDataState)
	}
	if !strings.Contains(rule.Data[0].Model.Expr, "pgbouncer_up") {
		t.Errorf("exporter alert does not query pgbouncer_up: %s", rule.Data[0].Model.Expr)
	}
}

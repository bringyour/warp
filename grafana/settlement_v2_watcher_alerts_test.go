package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

type settlementV2WatcherRule struct {
	snValidatorRule `yaml:",inline"`
	IsPaused        *bool `yaml:"isPaused"`
}

func settlementV2WatcherRules(t *testing.T) []settlementV2WatcherRule {
	t.Helper()
	// Read the actual embedded provisioning input, not a separate fixture:
	// before these rules existed, a stopped watcher could never raise an alert.
	data, err := alertingFs.ReadFile("alerting/settlement-v2-watcher.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		APIVersion int `yaml:"apiVersion"`
		Groups     []struct {
			OrgID    int                       `yaml:"orgId"`
			Name     string                    `yaml:"name"`
			Folder   string                    `yaml:"folder"`
			Interval string                    `yaml:"interval"`
			Rules    []settlementV2WatcherRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.APIVersion != 1 || len(document.Groups) != 1 {
		t.Fatalf("watcher provisioning version/groups = %d/%d, want 1/1", document.APIVersion, len(document.Groups))
	}
	group := document.Groups[0]
	if group.OrgID != 1 || group.Name != "sn-settlement-v2-watcher" || group.Folder != "urnetwork alerts" || group.Interval != "1m" {
		t.Fatalf("watcher alert group = %+v", group)
	}
	if len(group.Rules) != 2 {
		t.Fatalf("watcher alerts = %d, want separate no-run and no-success rules", len(group.Rules))
	}
	return group.Rules
}

// XOps SN-MAINNET-SETTLEMENT-V2-WATCHER.md specifies these two independent
// age limits after pool registration. The recorder emits Unix seconds;
// Planetoid's textfile collector adds env=main, host=planetoid, job=node.
func TestSettlementV2WatcherAlertsUsePublishedTimestampsAndLimits(t *testing.T) {
	required := map[string]struct {
		metric    string
		threshold float64
	}{
		"sn-settlement-v2-watcher-no-run":     {"last_run_timestamp_seconds", 7200},
		"sn-settlement-v2-watcher-no-success": {"last_success_timestamp_seconds", 10800},
	}
	for _, rule := range settlementV2WatcherRules(t) {
		want, ok := required[rule.UID]
		if !ok {
			t.Errorf("unexpected or duplicate watcher rule %q", rule.UID)
			continue
		}
		delete(required, rule.UID)
		if rule.Condition != "B" || len(rule.Data) != 2 || rule.Data[0].RefID != "A" || rule.Data[1].RefID != "B" {
			t.Errorf("%s must threshold query A in expression B", rule.UID)
			continue
		}
		query, condition := rule.Data[0], rule.Data[1]
		if query.DatasourceUID != "warp-mimir" || condition.DatasourceUID != "__expr__" {
			t.Errorf("%s must query the normal warp-mimir datasource", rule.UID)
		}
		// No > 0 filter: zero means the watcher has never succeeded, and must
		// stay an old timestamp rather than disappear from the age check.
		wantExpr := `time() - max(sn_settlement_v2_watcher_` + want.metric + `{env="main",host="planetoid",job="node"})`
		if query.Model.Expr != wantExpr {
			t.Errorf("%s query = %q, want %q", rule.UID, query.Model.Expr, wantExpr)
		}
		conditions := condition.Model.Conditions
		if len(conditions) != 1 || conditions[0].Evaluator.Type != "gt" || len(conditions[0].Evaluator.Params) != 1 || conditions[0].Evaluator.Params[0] != want.threshold {
			t.Errorf("%s threshold = %+v, want gt %v seconds", rule.UID, conditions, want.threshold)
		}
	}
	if len(required) != 0 {
		t.Errorf("missing watcher failure modes: %v", required)
	}
}

func TestSettlementV2WatcherAlertsPageOnMissingData(t *testing.T) {
	for _, rule := range settlementV2WatcherRules(t) {
		if rule.NoDataState != "Alerting" || rule.ExecErrState != "Error" {
			t.Errorf("%s must alert on missing telemetry and preserve query errors", rule.UID)
		}
		if rule.Labels["service"] != "sn-settlement-v2-watcher" || rule.Labels["severity"] != "page" {
			t.Errorf("%s routing labels = %v", rule.UID, rule.Labels)
		}
		if rule.IsPaused == nil || *rule.IsPaused || rule.For != "0s" {
			t.Errorf("%s must evaluate without an extra hold after the specified age limit", rule.UID)
		}
		if rule.Title == "" || rule.Annotations["summary"] == "" {
			t.Errorf("%s is missing its title or operator summary", rule.UID)
		}
	}
}

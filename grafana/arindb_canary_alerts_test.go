package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type arindbCanaryAlertRule struct {
	UID         string            `yaml:"uid"`
	Title       string            `yaml:"title"`
	NoDataState string            `yaml:"noDataState"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
	Data        []struct {
		RefID         string `yaml:"refId"`
		DatasourceUID string `yaml:"datasourceUid"`
		Model         struct {
			Expr       string `yaml:"expr"`
			Instant    bool   `yaml:"instant"`
			Conditions []struct {
				Evaluator struct {
					Params []float64 `yaml:"params"`
					Type   string    `yaml:"type"`
				} `yaml:"evaluator"`
			} `yaml:"conditions"`
		} `yaml:"model"`
	} `yaml:"data"`
}

func arindbCanaryAlertRules(t *testing.T) map[string]arindbCanaryAlertRule {
	t.Helper()
	data, err := os.ReadFile("alerting/arindb-canary.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Rules []arindbCanaryAlertRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	rules := map[string]arindbCanaryAlertRule{}
	for _, group := range document.Groups {
		for _, rule := range group.Rules {
			if _, repeated := rules[rule.UID]; repeated {
				t.Fatalf("rule uid %s is repeated", rule.UID)
			}
			rules[rule.UID] = rule
		}
	}
	return rules
}

// One exported gauge sample, as the server's stats collectors push it.
type arindbCanarySample struct {
	name   string
	labels map[string]string
	value  float64
}

// The one expression shape these rules use, `[time() - ]max by (labels)
// (metric{matchers})`, evaluated over samples at now: each group's max, or
// now minus it. Any other shape fails the test rather than evaluating.
var arindbCanaryExpressionPattern = regexp.MustCompile(`^(time\(\) - )?max by \(([a-z_, ]+)\) \(([a-z0-9_]+)(?:\{([^}]*)\})?\)$`)
var arindbCanaryMatcherPattern = regexp.MustCompile(`^([a-z_]+)(=~|=)"([^"]*)"$`)

func evaluateArindbCanaryExpression(t *testing.T, expr string, samples []arindbCanarySample, now float64) map[string]float64 {
	t.Helper()
	match := arindbCanaryExpressionPattern.FindStringSubmatch(expr)
	if match == nil {
		t.Fatalf("expression %q is not of the evaluated shape", expr)
	}
	sinceNow, by, metric, matcherText := match[1] != "", strings.Split(match[2], ", "), match[3], match[4]
	type matcher struct {
		label string
		re    *regexp.Regexp
	}
	matchers := []matcher{}
	if matcherText != "" {
		for _, part := range strings.Split(matcherText, ",") {
			m := arindbCanaryMatcherPattern.FindStringSubmatch(strings.TrimSpace(part))
			if m == nil {
				t.Fatalf("matcher %q of %q is not evaluated", part, expr)
			}
			pattern := regexp.QuoteMeta(m[3])
			if m[2] == "=~" {
				pattern = m[3]
			}
			matchers = append(matchers, matcher{label: m[1], re: regexp.MustCompile("^(?:" + pattern + ")$")})
		}
	}
	groups := map[string]float64{}
	for _, sample := range samples {
		if sample.name != metric {
			continue
		}
		selected := true
		for _, m := range matchers {
			selected = selected && m.re.MatchString(sample.labels[m.label])
		}
		if !selected {
			continue
		}
		keys := []string{}
		for _, label := range by {
			keys = append(keys, label+"="+sample.labels[label])
		}
		key := strings.Join(keys, ",")
		if current, ok := groups[key]; !ok || current < sample.value {
			groups[key] = sample.value
		}
	}
	if sinceNow {
		for key, value := range groups {
			groups[key] = now - value
		}
	}
	return groups
}

// The groups of a rule whose threshold holds.
func firingArindbCanaryGroups(t *testing.T, rule arindbCanaryAlertRule, samples []arindbCanarySample, now float64) []string {
	t.Helper()
	if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
		t.Fatalf("rule %s is not one query and one threshold", rule.UID)
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 {
		t.Fatalf("rule %s threshold %s %v is not a single greater-than", rule.UID, evaluator.Type, evaluator.Params)
	}
	firing := []string{}
	for group, value := range evaluateArindbCanaryExpression(t, rule.Data[0].Model.Expr, samples, now) {
		if evaluator.Params[0] < value {
			firing = append(firing, group)
		}
	}
	return firing
}

func arindbCanaryStateSamples(env string, active string) []arindbCanarySample {
	samples := []arindbCanarySample{}
	for _, state := range []string{"single", "warming", "latest", "fallback"} {
		value := 0.0
		if state == active {
			value = 1
		}
		samples = append(samples, arindbCanarySample{name: "urnetwork_stats_arindb_canary_state", labels: map[string]string{"env": env, "state": state}, value: value})
	}
	return samples
}

// The two rules that page: a fallback, and a Speed or Online loss above the
// breaker's threshold, which only risk can cause.
func TestArindbCanaryAlertsPageOnFallbackAndRiskDrivenLoss(t *testing.T) {
	rules := arindbCanaryAlertRules(t)
	for uid, title := range map[string]string{"arindb-fallback-active": "ArinDbFallbackActive", "arindb-risk-supply-loss": "ArinDbRiskSupplyLoss"} {
		rule, ok := rules[uid]
		if !ok {
			t.Fatalf("missing %s", uid)
		}
		if rule.Title != title || rule.Labels["severity"] != "page" || rule.For != "10m" || rule.Data[0].DatasourceUID != "warp-mimir" || !rule.Data[0].Model.Instant {
			t.Errorf("%s: title=%s severity=%s for=%s", uid, rule.Title, rule.Labels["severity"], rule.For)
		}
	}
	// two taskworkers export the same decision; one environment falls back
	samples := []arindbCanarySample{
		{name: "urnetwork_stats_arindb_fallback_active", labels: map[string]string{"env": "main", "host": "worker-a"}, value: 1},
		{name: "urnetwork_stats_arindb_fallback_active", labels: map[string]string{"env": "main", "host": "worker-b"}, value: 1},
		{name: "urnetwork_stats_arindb_fallback_active", labels: map[string]string{"env": "beta", "host": "worker-c"}, value: 0},
	}
	if firing := firingArindbCanaryGroups(t, rules["arindb-fallback-active"], samples, 0); len(firing) != 1 || firing[0] != "env=main" {
		t.Fatalf("fallback fires for %v, want env=main", firing)
	}
	losses := []arindbCanarySample{
		{name: "urnetwork_stats_arindb_loss_ratio", labels: map[string]string{"env": "main", "bucket": "quality"}, value: 0.5},
		{name: "urnetwork_stats_arindb_loss_ratio", labels: map[string]string{"env": "main", "bucket": "speed"}, value: 0.10},
		{name: "urnetwork_stats_arindb_loss_ratio", labels: map[string]string{"env": "main", "bucket": "online"}, value: 0.11},
	}
	// Quality is the fallback's to repair; exactly the threshold holds
	if firing := firingArindbCanaryGroups(t, rules["arindb-risk-supply-loss"], losses, 0); len(firing) != 1 || firing[0] != "env=main,bucket=online" {
		t.Fatalf("risk loss fires for %v, want only online", firing)
	}
}

// The warnings: no usable old database for an hour, warming for two hours,
// and a decision more than 30 minutes old.
func TestArindbCanaryAlertsWarnOnUnavailableWarmingAndStale(t *testing.T) {
	rules := arindbCanaryAlertRules(t)
	for uid, want := range map[string]struct{ title, holdFor string }{
		"arindb-canary-unavailable": {title: "ArinDbCanaryUnavailable", holdFor: "1h"},
		"arindb-canary-warming":     {title: "ArinDbCanaryWarming", holdFor: "2h"},
		"arindb-decision-stale":     {title: "ArinDbDecisionStale", holdFor: "1m"},
	} {
		rule, ok := rules[uid]
		if !ok {
			t.Fatalf("missing %s", uid)
		}
		if rule.Title != want.title || rule.Labels["severity"] != "warn" || rule.For != want.holdFor || rule.Data[0].DatasourceUID != "warp-mimir" {
			t.Errorf("%s: title=%s severity=%s for=%s", uid, rule.Title, rule.Labels["severity"], rule.For)
		}
	}
	for _, c := range []struct {
		state       string
		unavailable bool
		warming     bool
	}{
		{state: "single", unavailable: true},
		{state: "warming", warming: true},
		{state: "latest"},
		{state: "fallback"},
	} {
		samples := arindbCanaryStateSamples("main", c.state)
		if firing := firingArindbCanaryGroups(t, rules["arindb-canary-unavailable"], samples, 0); (len(firing) == 1) != c.unavailable {
			t.Errorf("state %s: unavailable fires for %v", c.state, firing)
		}
		if firing := firingArindbCanaryGroups(t, rules["arindb-canary-warming"], samples, 0); (len(firing) == 1) != c.warming {
			t.Errorf("state %s: warming fires for %v", c.state, firing)
		}
	}
	now := 1_800_000_000.0
	for _, c := range []struct {
		age   float64
		stale bool
	}{{age: 60}, {age: 1800}, {age: 1801, stale: true}} {
		samples := []arindbCanarySample{{name: "urnetwork_stats_arindb_decision_seconds", labels: map[string]string{"env": "main"}, value: now - c.age}}
		if firing := firingArindbCanaryGroups(t, rules["arindb-decision-stale"], samples, now); (len(firing) == 1) != c.stale {
			t.Errorf("decision %v s old: stale fires for %v", c.age, firing)
		}
	}
}

// Every rule names the operator's next step and treats a missing series as
// no alert: a build without the canary exports none, and a stalled indexer
// keeps its last decision time for the stale rule.
func TestArindbCanaryAlertsAreActionableAndQuietWithoutTheCanary(t *testing.T) {
	rules := arindbCanaryAlertRules(t)
	if len(rules) != 5 {
		t.Fatalf("%d canary rules, want 5", len(rules))
	}
	for uid, rule := range rules {
		if rule.NoDataState != "OK" {
			t.Errorf("%s noDataState %s, want OK", uid, rule.NoDataState)
		}
		if summary := rule.Annotations["summary"]; summary == "" || !strings.Contains(summary, "{{ $labels.env }}") {
			t.Errorf("%s summary does not name the environment: %q", uid, summary)
		}
		if !strings.Contains(rule.Data[0].Model.Expr, "urnetwork_stats_arindb_") || !strings.Contains(rule.Data[0].Model.Expr, "max by (env") {
			t.Errorf("%s does not read the replicated canary gauges with max by env: %s", uid, rule.Data[0].Model.Expr)
		}
	}
	if !strings.Contains(rules["arindb-fallback-active"].Annotations["summary"], "ARIN_PREVIOUS_DATABASE_FILE") {
		t.Error("the fallback page does not name the baseline pin")
	}
}

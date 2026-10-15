package main

import (
	"os"
	"regexp"
	"slices"
	"strconv"
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

// One group of an evaluated expression.
type arindbCanaryGroup struct {
	labels map[string]string
	value  float64
}

func (self arindbCanaryGroup) key(labels []string) string {
	keys := []string{}
	for _, label := range labels {
		keys = append(keys, label+"="+self.labels[label])
	}
	return strings.Join(keys, ",")
}

// The expression shapes these rules use, `[time() - ]max by (labels)
// (metric{matchers})`, optionally `and on (labels) (<that shape> >= n)`,
// evaluated over samples at now: each group's max, or now minus it, kept
// where the sampled side holds. Any other shape fails the test rather than
// evaluating.
var arindbCanaryExpressionPattern = regexp.MustCompile(`^(time\(\) - )?max by \(([a-z_, ]+)\) \(([a-z0-9_]+)(?:\{([^}]*)\})?\)$`)
var arindbCanaryAndOnPattern = regexp.MustCompile(`^(.+\)) and on \(([a-z_, ]+)\) \((.+\)) >= ([0-9.]+)\)$`)
var arindbCanaryMatcherPattern = regexp.MustCompile(`^([a-z_]+)(=~|=)"([^"]*)"$`)

func evaluateArindbCanaryExpression(t *testing.T, expr string, samples []arindbCanarySample, now float64) []arindbCanaryGroup {
	t.Helper()
	if match := arindbCanaryAndOnPattern.FindStringSubmatch(expr); match != nil {
		on := strings.Split(match[2], ", ")
		floor, err := strconv.ParseFloat(match[4], 64)
		if err != nil {
			t.Fatal(err)
		}
		sampled := map[string]bool{}
		for _, group := range evaluateArindbCanaryExpression(t, match[3], samples, now) {
			if floor <= group.value {
				sampled[group.key(on)] = true
			}
		}
		kept := []arindbCanaryGroup{}
		for _, group := range evaluateArindbCanaryExpression(t, match[1], samples, now) {
			if sampled[group.key(on)] {
				kept = append(kept, group)
			}
		}
		return kept
	}
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
	groups := map[string]*arindbCanaryGroup{}
	keys := []string{}
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
		labels := map[string]string{}
		for _, label := range by {
			labels[label] = sample.labels[label]
		}
		group := arindbCanaryGroup{labels: labels, value: sample.value}
		key := group.key(by)
		if current, ok := groups[key]; !ok {
			groups[key] = &group
			keys = append(keys, key)
		} else if current.value < sample.value {
			current.value = sample.value
		}
	}
	evaluated := []arindbCanaryGroup{}
	for _, key := range keys {
		group := *groups[key]
		if sinceNow {
			group.value = now - group.value
		}
		evaluated = append(evaluated, group)
	}
	return evaluated
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
	by := []string{"env"}
	if match := regexp.MustCompile(`^(?:time\(\) - )?max by \(([a-z_, ]+)\)`).FindStringSubmatch(rule.Data[0].Model.Expr); match != nil {
		by = strings.Split(match[1], ", ")
	}
	firing := []string{}
	for _, group := range evaluateArindbCanaryExpression(t, rule.Data[0].Model.Expr, samples, now) {
		if evaluator.Params[0] < group.value {
			firing = append(firing, group.key(by))
		}
	}
	slices.Sort(firing)
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
	losses := append(arindbCanaryOldSupply("main", 20),
		arindbCanarySample{name: "urnetwork_stats_arindb_loss_ratio", labels: map[string]string{"env": "main", "bucket": "quality"}, value: 0.5},
		arindbCanarySample{name: "urnetwork_stats_arindb_loss_ratio", labels: map[string]string{"env": "main", "bucket": "speed"}, value: 0.10},
		arindbCanarySample{name: "urnetwork_stats_arindb_loss_ratio", labels: map[string]string{"env": "main", "bucket": "online"}, value: 0.11},
	)
	// Quality is the fallback's to repair; exactly the threshold holds
	if firing := firingArindbCanaryGroups(t, rules["arindb-risk-supply-loss"], losses, 0); len(firing) != 1 || firing[0] != "env=main,bucket=online" {
		t.Fatalf("risk loss fires for %v, want only online", firing)
	}
	// a bucket with less than 20 paired providers of old supply is too small
	if firing := firingArindbCanaryGroups(t, rules["arindb-risk-supply-loss"], append(arindbCanaryOldSupply("main", 19), losses[6:]...), 0); len(firing) != 0 {
		t.Fatalf("risk loss fires below the sample floor for %v", firing)
	}
}

// Every bucket's paired supply under the old database in env.
func arindbCanaryOldSupply(env string, old float64) []arindbCanarySample {
	samples := []arindbCanarySample{}
	for _, bucket := range []string{"quality", "speed", "online"} {
		samples = append(samples, arindbCanarySample{name: "urnetwork_stats_arindb_providers", labels: map[string]string{"env": env, "bucket": bucket, "database": "old"}, value: old})
		samples = append(samples, arindbCanarySample{name: "urnetwork_stats_arindb_providers", labels: map[string]string{"env": env, "bucket": bucket, "database": "latest"}, value: 1000})
	}
	return samples
}

// The breaker sees only net losses of a covered comparison. A tripped warming
// comparison, a lost protection, a cohort shrinking before the canary can
// compare it, a serving epoch switching back and forth and a decision stalled
// for 90 minutes page on their own.
func TestArindbCanaryAlertsPageOnWhatTheBreakerCannotSee(t *testing.T) {
	rules := arindbCanaryAlertRules(t)
	for uid, want := range map[string]struct{ title, holdFor string }{
		"arindb-decision-stalled": {title: "ArinDbDecisionStalled", holdFor: "1m"},
		"arindb-warming-tripped":  {title: "ArinDbWarmingTripped", holdFor: "10m"},
		"arindb-protection-lost":  {title: "ArinDbProtectionLost", holdFor: "10m"},
		"arindb-cohort-shrink":    {title: "ArinDbCohortShrink", holdFor: "10m"},
		"arindb-serving-flapping": {title: "ArinDbServingFlapping", holdFor: "5m"},
	} {
		rule, ok := rules[uid]
		if !ok {
			t.Fatalf("missing %s", uid)
		}
		if rule.Title != want.title || rule.Labels["severity"] != "page" || rule.For != want.holdFor || rule.Data[0].DatasourceUID != "warp-mimir" {
			t.Errorf("%s: title=%s severity=%s for=%s", uid, rule.Title, rule.Labels["severity"], rule.For)
		}
	}
	for _, c := range []struct {
		uid     string
		samples []arindbCanarySample
		firing  []string
	}{
		{uid: "arindb-warming-tripped", firing: []string{"env=main"}, samples: []arindbCanarySample{
			{name: "urnetwork_stats_arindb_decision_flags", labels: map[string]string{"env": "main", "flag": "warming_tripped"}, value: 1},
			{name: "urnetwork_stats_arindb_decision_flags", labels: map[string]string{"env": "beta", "flag": "warming_serves_latest"}, value: 1}}},
		{uid: "arindb-protection-lost", firing: []string{"env=main,flag=fallback_dropped", "env=main,flag=latest_unavailable"}, samples: []arindbCanarySample{
			{name: "urnetwork_stats_arindb_decision_flags", labels: map[string]string{"env": "main", "flag": "latest_unavailable"}, value: 1},
			{name: "urnetwork_stats_arindb_decision_flags", labels: map[string]string{"env": "main", "flag": "fallback_dropped"}, value: 1},
			{name: "urnetwork_stats_arindb_decision_flags", labels: map[string]string{"env": "main", "flag": "pair_carried"}, value: 1}}},
		{uid: "arindb-serving-flapping", firing: []string{"env=main"}, samples: []arindbCanarySample{
			{name: "urnetwork_stats_arindb_serving_changes", labels: map[string]string{"env": "main"}, value: 5},
			{name: "urnetwork_stats_arindb_serving_changes", labels: map[string]string{"env": "beta"}, value: 4}}},
		{uid: "arindb-decision-stalled", firing: []string{"env=main"}, samples: []arindbCanarySample{
			{name: "urnetwork_stats_arindb_decision_seconds", labels: map[string]string{"env": "main"}, value: 1_800_000_000 - 5401},
			{name: "urnetwork_stats_arindb_decision_seconds", labels: map[string]string{"env": "beta"}, value: 1_800_000_000 - 5400}}},
	} {
		firing := firingArindbCanaryGroups(t, rules[c.uid], c.samples, 1_800_000_000)
		if !slices.Equal(firing, c.firing) {
			t.Errorf("%s fires for %v, want %v", c.uid, firing, c.firing)
		}
	}
}

// A gain or gross churn with a sample, and an unverified latest served while
// warming, warn after 30 minutes: a deliberate catalog expansion gains and
// churns too, and warming ends on its own once coverage returns.
func TestArindbCanaryAlertsWarnOnGainChurnAndAnUnverifiedLatest(t *testing.T) {
	rules := arindbCanaryAlertRules(t)
	for uid, title := range map[string]string{
		"arindb-supply-gain":           "ArinDbSupplyGain",
		"arindb-supply-churn":          "ArinDbSupplyChurn",
		"arindb-warming-serves-latest": "ArinDbWarmingServesLatest",
	} {
		rule, ok := rules[uid]
		if !ok {
			t.Fatalf("missing %s", uid)
		}
		if rule.Title != title || rule.Labels["severity"] != "warn" || rule.For != "30m" || rule.Data[0].DatasourceUID != "warp-mimir" {
			t.Errorf("%s: title=%s severity=%s for=%s", uid, rule.Title, rule.Labels["severity"], rule.For)
		}
	}
	for _, c := range []struct {
		uid     string
		samples []arindbCanarySample
		firing  []string
	}{
		{uid: "arindb-supply-gain", firing: []string{"env=main,bucket=quality"}, samples: append(arindbCanaryOldSupply("main", 20),
			arindbCanarySample{name: "urnetwork_stats_arindb_gain_ratio", labels: map[string]string{"env": "main", "bucket": "quality"}, value: 0.11},
			arindbCanarySample{name: "urnetwork_stats_arindb_gain_ratio", labels: map[string]string{"env": "main", "bucket": "speed"}, value: 0.10})},
		{uid: "arindb-supply-gain", samples: append(arindbCanaryOldSupply("main", 19),
			arindbCanarySample{name: "urnetwork_stats_arindb_gain_ratio", labels: map[string]string{"env": "main", "bucket": "quality"}, value: 0.5})},
		{uid: "arindb-supply-churn", firing: []string{"env=main,bucket=online"}, samples: append(arindbCanaryOldSupply("main", 100),
			arindbCanarySample{name: "urnetwork_stats_arindb_churn_ratio", labels: map[string]string{"env": "main", "bucket": "online"}, value: 0.21},
			arindbCanarySample{name: "urnetwork_stats_arindb_churn_ratio", labels: map[string]string{"env": "main", "bucket": "quality"}, value: 0.20})},
		{uid: "arindb-warming-serves-latest", firing: []string{"env=main"}, samples: []arindbCanarySample{
			{name: "urnetwork_stats_arindb_decision_flags", labels: map[string]string{"env": "main", "flag": "warming_serves_latest"}, value: 1},
			{name: "urnetwork_stats_arindb_decision_flags", labels: map[string]string{"env": "beta", "flag": "warming_tripped"}, value: 1}}},
	} {
		firing := firingArindbCanaryGroups(t, rules[c.uid], c.samples, 1_800_000_000)
		if !slices.Equal(firing, c.firing) {
			t.Errorf("%s fires for %v, want %v", c.uid, firing, c.firing)
		}
	}
}

// A shrinking cohort pages only where a release can explain it: a pair
// compared for under two hours, or latest lookups failing, as each process
// counts them. A Connect outage or a restart shrinks the cohort too.
func TestArindbCanaryAlertsGateTheCohortPageOnARelease(t *testing.T) {
	rule, ok := arindbCanaryAlertRules(t)["arindb-cohort-shrink"]
	if !ok {
		t.Fatal("missing arindb-cohort-shrink")
	}
	want := `max by (env) (urnetwork_stats_arindb_cohort_loss_ratio) and on (env) (max by (env) (urnetwork_stats_arindb_cohort_providers{reference="reference"}) >= 100) and on (env) ((time() - max by (env) (urnetwork_stats_arindb_pair_since_seconds) < 7200) or on (env) (sum by (env) (rate(urnetwork_arin_lookup_errors_total{slot="latest"}[30m])) > 0))`
	if rule.Data[0].Model.Expr != want {
		t.Fatalf("cohort rule expression %s, want %s", rule.Data[0].Model.Expr, want)
	}
	if evaluator := rule.Data[1].Model.Conditions[0].Evaluator; evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != 0.1 {
		t.Fatalf("cohort rule threshold %s %v", evaluator.Type, evaluator.Params)
	}
}

// Readers that miss the decision warn: the share of every process's reads
// that were not ok, summed as rates across them, above 5% for 15 minutes.
func TestArindbCanaryAlertsWarnWhenReadersMissTheDecision(t *testing.T) {
	rule, ok := arindbCanaryAlertRules(t)["arindb-decision-reads-not-ok"]
	if !ok {
		t.Fatal("missing arindb-decision-reads-not-ok")
	}
	if rule.Title != "ArinDbDecisionReadsNotOk" || rule.Labels["severity"] != "warn" || rule.For != "15m" || rule.NoDataState != "OK" {
		t.Fatalf("reads rule: title=%s severity=%s for=%s", rule.Title, rule.Labels["severity"], rule.For)
	}
	want := `sum by (env) (rate(urnetwork_arindb_decision_reads_total{outcome!="ok"}[10m])) / sum by (env) (rate(urnetwork_arindb_decision_reads_total[10m]))`
	if rule.Data[0].Model.Expr != want {
		t.Fatalf("reads rule expression %s, want %s", rule.Data[0].Model.Expr, want)
	}
	if evaluator := rule.Data[1].Model.Conditions[0].Evaluator; evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != 0.05 {
		t.Fatalf("reads rule threshold %s %v", evaluator.Type, evaluator.Params)
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
	if len(rules) != 14 {
		t.Fatalf("%d canary rules, want 14", len(rules))
	}
	for uid, rule := range rules {
		if rule.NoDataState != "OK" {
			t.Errorf("%s noDataState %s, want OK", uid, rule.NoDataState)
		}
		if summary := rule.Annotations["summary"]; summary == "" || !strings.Contains(summary, "{{ $labels.env }}") {
			t.Errorf("%s summary does not name the environment: %q", uid, summary)
		}
		// the stats gauges are replicated by every taskworker and read with
		// max; the decision reads are each process's own, summed as rates
		expr := rule.Data[0].Model.Expr
		replicated := strings.Contains(expr, "urnetwork_stats_arindb_") && strings.Contains(expr, "max by (env")
		perProcess := strings.Contains(expr, "urnetwork_arindb_decision_reads_total") && strings.Contains(expr, "sum by (env)")
		if !replicated && !perProcess {
			t.Errorf("%s reads neither the replicated canary gauges with max by env nor the decision reads summed by env: %s", uid, expr)
		}
	}
	if !strings.Contains(rules["arindb-fallback-active"].Annotations["summary"], "ARIN_PREVIOUS_DATABASE_FILE") {
		t.Error("the fallback page does not name the baseline pin")
	}
}

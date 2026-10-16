package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/coreos/go-semver/semver"
)

// Used by the real deployment as well as --preflight. It has no mutation
// dependencies, and bounds each strongly consistent selector read separately.
func verifyDeploymentSelectors(ctx context.Context, client deploymentRecordReader, env, service string, blocks []string, initialize bool) ([]string, error) {
	versions := []string{}
	for _, block := range blocks {
		readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		record, err := client.GetDeploymentRecordConsistent(readCtx, env, service, block)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("cannot read deployment selector for %s/%s/%s: %w", env, service, block, err)
		}
		if record == nil {
			if initialize {
				continue
			}
			return nil, fmt.Errorf("deployment selector absent for %s/%s/%s; explicit bootstrap is required", env, service, block)
		}
		if _, err := semver.NewVersion(record.Version); err != nil {
			return nil, fmt.Errorf("invalid deployment selector for %s/%s/%s", env, service, block)
		}
		if !slices.Contains(versions, record.Version) {
			versions = append(versions, record.Version)
		}
	}
	return versions, nil
}

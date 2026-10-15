package main

import (
	"context"
	"fmt"
	"slices"

	"github.com/coreos/go-semver/semver"
	"github.com/urnetwork/warp/warpctl/dynamo"
)

type deploymentRecordReader interface {
	GetDeploymentRecordConsistent(context.Context, string, string, string) (*dynamo.DeploymentRecord, error)
}

type deploymentVersionSampler func(string, string, ...string) (map[string]map[semver.Version]float32, error)

// Plan every selected block before performing any promotion. An unavailable
// status route is never evidence of an absent deployment: only a successful,
// strongly consistent selector read can establish that. Existing deployments
// retain the ordinary --only-older live-version check.
func prepareInitializedDeployment(
	ctx context.Context,
	client deploymentRecordReader,
	env, service, version string,
	blocks []string,
	sample deploymentVersionSampler,
) (selected []string, initialize map[string]bool, err error) {
	if _, err := semver.NewVersion(version); err != nil {
		return nil, nil, fmt.Errorf("initial deployment target is not a semantic version")
	}
	if err := validateBlockStatusSampling(env, service); err != nil {
		return nil, nil, err
	}
	initialize = map[string]bool{}
	existing := []string{}
	for _, block := range blocks {
		record, err := client.GetDeploymentRecordConsistent(ctx, env, service, block)
		if err != nil {
			return nil, nil, err
		}
		if record == nil {
			initialize[block] = true
			continue
		}
		if _, err := semver.NewVersion(record.Version); err != nil {
			return nil, nil, fmt.Errorf("deployment record for block %q has an invalid version", block)
		}
		if record.Version == version && record.InitializedVersion == version {
			Err.Printf("Block %s was already initialized to %s; no change.", block, version)
			continue
		}
		existing = append(existing, block)
	}
	if len(existing) != 0 {
		versions, err := sample(env, service, existing...)
		if err != nil {
			return nil, nil, err
		}
		existing, err = filterOlderDeployBlocks(version, existing, versions)
		if err != nil {
			return nil, nil, err
		}
	}
	for _, block := range blocks {
		if initialize[block] || slices.Contains(existing, block) {
			selected = append(selected, block)
		}
	}
	return selected, initialize, nil
}

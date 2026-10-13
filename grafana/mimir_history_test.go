package main

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Mimir 3.1.1 defaults for the read-path settings below. A child runs with
// these whenever the rendered document omits the key.
const (
	// -querier.query-store-after
	mimirDefaultQueryStoreAfter = 12 * time.Hour
	// -blocks-storage.bucket-store.ignore-blocks-within
	mimirDefaultIgnoreBlocksWithin = 10 * time.Hour
	// -compactor.cleanup-interval, which also updates the bucket index
	mimirDefaultCleanupInterval = 15 * time.Minute
	// -blocks-storage.bucket-store.sync-interval
	mimirDefaultSyncInterval = 15 * time.Minute
	// -querier.query-ingesters-within
	mimirDefaultQueryIngestersWithin = 13 * time.Hour
)

// The rendered settings that decide whether a block in the bucket is readable.
type mimirReadPath struct {
	flushBlocksOnShutdown bool
	queryStoreAfter       time.Duration
	queryIngestersWithin  time.Duration
	ignoreBlocksWithin    time.Duration
	cleanupInterval       time.Duration
	syncInterval          time.Duration
}

// renderedMimirReadPath renders the complete child document, the same one
// renderMimirConfig writes, and reads back the read-path settings. An omitted
// key keeps Mimir's default.
func renderedMimirReadPath(t *testing.T) mimirReadPath {
	t.Helper()
	hostSettings := &HostSettings{
		Routes: map[string]string{
			"edge-a": "192.0.2.10",
			"edge-b": "192.0.2.11",
			"minio":  "192.0.2.20",
		},
	}
	grafanaConfig := &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "minio"},
	}
	rendered, err := yaml.Marshal(mimirConfig("edge-a", "192.0.2.10", 3201, 16491, 16493, hostSettings, []string{"edge-a", "edge-b"}, grafanaConfig))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Target  string `yaml:"target"`
		Querier struct {
			QueryStoreAfter *string `yaml:"query_store_after"`
		} `yaml:"querier"`
		Limits struct {
			QueryIngestersWithin *string `yaml:"query_ingesters_within"`
		} `yaml:"limits"`
		Compactor struct {
			CleanupInterval *string `yaml:"cleanup_interval"`
		} `yaml:"compactor"`
		BlocksStorage struct {
			TSDB struct {
				FlushBlocksOnShutdown bool `yaml:"flush_blocks_on_shutdown"`
			} `yaml:"tsdb"`
			BucketStore struct {
				SyncInterval       *string `yaml:"sync_interval"`
				IgnoreBlocksWithin *string `yaml:"ignore_blocks_within"`
			} `yaml:"bucket_store"`
		} `yaml:"blocks_storage"`
	}
	if err := yaml.Unmarshal(rendered, &parsed); err != nil {
		t.Fatal(err)
	}
	// every replica runs the querier, store-gateway and compactor modules
	if parsed.Target != "all" {
		t.Fatalf("Mimir target = %q, want all:\n%s", parsed.Target, rendered)
	}
	duration := func(name string, value *string, mimirDefault time.Duration) time.Duration {
		if value == nil {
			return mimirDefault
		}
		interval, err := time.ParseDuration(*value)
		if err != nil {
			t.Fatalf("rendered %s %q is not a duration: %s", name, *value, err)
		}
		return interval
	}
	return mimirReadPath{
		flushBlocksOnShutdown: parsed.BlocksStorage.TSDB.FlushBlocksOnShutdown,
		queryStoreAfter:       duration("querier.query_store_after", parsed.Querier.QueryStoreAfter, mimirDefaultQueryStoreAfter),
		queryIngestersWithin:  duration("limits.query_ingesters_within", parsed.Limits.QueryIngestersWithin, mimirDefaultQueryIngestersWithin),
		ignoreBlocksWithin:    duration("blocks_storage.bucket_store.ignore_blocks_within", parsed.BlocksStorage.BucketStore.IgnoreBlocksWithin, mimirDefaultIgnoreBlocksWithin),
		cleanupInterval:       duration("compactor.cleanup_interval", parsed.Compactor.CleanupInterval, mimirDefaultCleanupInterval),
		syncInterval:          duration("blocks_storage.bucket_store.sync_interval", parsed.BlocksStorage.BucketStore.SyncInterval, mimirDefaultSyncInterval),
	}
}

// storeServes reports whether a range query evaluated at now reads a block that
// the bucket index already lists, following Mimir 3.1.1:
//   - querier.go ShouldQueryBlockStore skips the store-gateways when the query
//     starts at or after now-query_store_after;
//   - blocks_store_queryable.go queryWithConsistencyCheck ends the store request
//     at now-query_store_after;
//   - metadata_fetcher_filters.go minTimeMetaFilter keeps a store-gateway from
//     loading a block whose min time is at or after now-ignore_blocks_within.
//
// Zero disables each of these limits.
func (self mimirReadPath) storeServes(now time.Time, queryStart time.Time, queryEnd time.Time, blockStart time.Time, blockEnd time.Time) bool {
	storeEnd := queryEnd
	if self.queryStoreAfter != 0 {
		storeMax := now.Add(-self.queryStoreAfter)
		if !queryStart.Before(storeMax) {
			return false
		}
		if storeMax.Before(storeEnd) {
			storeEnd = storeMax
		}
	}
	if 0 < self.ignoreBlocksWithin && !blockStart.Before(now.Add(-self.ignoreBlocksWithin)) {
		return false
	}
	return !blockStart.After(storeEnd) && queryStart.Before(blockEnd)
}

// readableAfterUpload is the worst case from a block's upload until queries
// can read it. The compactor adds the block to the bucket index on its next
// cleanup (the interval carries 10% jitter). The queriers reload the index and
// the store-gateways sync it about one sync_interval later, plus the index
// loader's one-minute check.
func (self mimirReadPath) readableAfterUpload() time.Duration {
	return self.cleanupInterval*11/10 + self.syncInterval + time.Minute
}

// A grafana deploy replaces every Mimir child within one warpctl polling
// window. The old ingesters flush their heads to MinIO on shutdown, and the
// new ones start with empty heads. After the 2026-10-13 deploy, the bucket held
// the two blocks that the replaced ingesters flushed (uploaded 06:02:47 to
// 06:03:18Z) and the 02:00-04:00 block shipped before it. Yet every host's
// range queries returned nothing between now-12h and the restart: Mimir's
// defaults read the last 12 hours from the ingesters alone, and store-gateways
// skip blocks younger than 10 hours.
func TestMimirReadsTheHeadThatReplacedIngestersFlushed(t *testing.T) {
	readPath := renderedMimirReadPath(t)
	if !readPath.flushBlocksOnShutdown {
		t.Fatal("Mimir discards the head of a replaced ingester instead of flushing it")
	}

	restart := time.Date(2026, 10, 13, 6, 3, 18, 0, time.UTC)
	blocks := []struct {
		start time.Time
		end   time.Time
	}{
		// shipped by the old ingesters before the deploy
		{time.Date(2026, 10, 13, 2, 0, 0, 0, time.UTC), time.Date(2026, 10, 13, 4, 0, 0, 0, time.UTC)},
		// flushed by the old ingesters on shutdown
		{time.Date(2026, 10, 13, 4, 0, 0, 0, time.UTC), time.Date(2026, 10, 13, 6, 0, 0, 0, time.UTC)},
		{time.Date(2026, 10, 13, 6, 0, 0, 0, time.UTC), restart},
	}
	// Query once the compactor has indexed the flushed blocks, and again hours
	// later.
	for _, elapsed := range []time.Duration{readPath.readableAfterUpload(), 6 * time.Hour} {
		now := restart.Add(elapsed)
		for _, queryRange := range []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour} {
			queryStart := now.Add(-queryRange)
			unreadable := []string{}
			for _, block := range blocks {
				if queryStart.Before(block.end) && !readPath.storeServes(now, queryStart, now, block.start, block.end) {
					unreadable = append(unreadable, block.start.Format("15:04:05")+"-"+block.end.Format("15:04:05"))
				}
			}
			if 0 < len(unreadable) {
				t.Errorf("%s after the deploy, a %s range query cannot read the blocks %s", elapsed, queryRange, strings.Join(unreadable, ", "))
			}
		}
	}

	// The new generation holds none of the old heads, so the history before the
	// restart stays unreadable until the compactor indexes the flushed blocks.
	if 10*time.Minute < readPath.readableAfterUpload() {
		t.Errorf("history before a deploy stays unreadable for up to %s after it", readPath.readableAfterUpload())
	}
}

// The querier asks the store-gateways for every block the bucket index lists in
// its store range, and fails the query's consistency check when no
// store-gateway has loaded one of them. So the store-gateways must load every
// block young enough for that range. Mimir also refuses to start when
// query_store_after is nonzero and not below query_ingesters_within.
func TestMimirStoreGatewaysLoadEveryBlockTheQueriersRequest(t *testing.T) {
	readPath := renderedMimirReadPath(t)
	if readPath.queryStoreAfter == 0 {
		if 0 < readPath.ignoreBlocksWithin {
			t.Fatalf("queriers read every block but store-gateways skip those younger than %s", readPath.ignoreBlocksWithin)
		}
	} else {
		if readPath.queryStoreAfter < readPath.ignoreBlocksWithin {
			t.Fatalf("queriers read blocks older than %s but store-gateways skip those younger than %s", readPath.queryStoreAfter, readPath.ignoreBlocksWithin)
		}
		if readPath.queryIngestersWithin != 0 && readPath.queryIngestersWithin <= readPath.queryStoreAfter {
			t.Fatalf("Mimir rejects query_store_after %s at or above query_ingesters_within %s", readPath.queryStoreAfter, readPath.queryIngestersWithin)
		}
	}
}

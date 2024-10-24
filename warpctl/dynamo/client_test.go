package dynamo_test

import (
	"context"
	"os"
	"testing"

	"bringyour.com/warpctl/dynamo"
)

// XTestClient is a test function that tests the dynamo client
// it requires AWS credentials to be set in the environment
// and will fail if they are not set
func XTestClient(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "...")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "...")

	dc, err := dynamo.NewClient()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	err = dc.UpdateVersion(ctx, "dev", "warpctl", "test", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	lv, err := dc.GetLatestVersion(ctx, "dev", "warpctl", "test")
	if err != nil {
		t.Fatal(err)
	}

	if lv != "1.0.0" {
		t.Fatalf("expected 1.0.0, got %s", lv)
	}

}

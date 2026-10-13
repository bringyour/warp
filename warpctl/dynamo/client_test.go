package dynamo_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/warp/warpctl/dynamo"
)

// TestClientLive writes and reads the real deployment-blocks table in
// us-west-1 (key dev-warpctl-test) with the AWS credentials in the
// environment. It runs only with WARP_DYNAMO_LIVE=1;
// TestClientUpdateThenGetLatestVersion covers the same calls offline.
func TestClientLive(t *testing.T) {
	if os.Getenv("WARP_DYNAMO_LIVE") != "1" {
		t.Skip("set WARP_DYNAMO_LIVE=1 to write and read the real deployment-blocks table")
	}

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

// The TestClientLive round trip against a loopback fake of the two DynamoDB
// operations the client uses, with fixture credentials and none of the
// caller's AWS profile, files, metadata service or endpoint-ignore setting.
func TestClientUpdateThenGetLatestVersion(t *testing.T) {
	type request struct {
		target string
		body   map[string]any
	}
	var mu sync.Mutex
	var requests []request
	var item any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); !strings.Contains(auth, "/us-west-1/dynamodb/aws4_request") {
			t.Errorf("request is not signed for dynamodb in us-west-1: %q", auth)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		defer mu.Unlock()
		target := r.Header.Get("X-Amz-Target")
		requests = append(requests, request{target: target, body: body})
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		switch target {
		case "DynamoDB_20120810.PutItem":
			item = body["Item"]
			w.Write([]byte("{}"))
		case "DynamoDB_20120810.GetItem":
			json.NewEncoder(w).Encode(map[string]any{"Item": item})
		default:
			http.Error(w, "unexpected operation", 400)
		}
	}))
	defer server.Close()
	awsEmpty := filepath.Join(t.TempDir(), "aws-empty")
	if err := os.WriteFile(awsEmpty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"AWS_ACCESS_KEY_ID": "fixture", "AWS_SECRET_ACCESS_KEY": "fixture", "AWS_SESSION_TOKEN": "",
		"AWS_PROFILE": "", "AWS_SHARED_CREDENTIALS_FILE": awsEmpty, "AWS_CONFIG_FILE": awsEmpty,
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_ENDPOINT_URL_DYNAMODB": server.URL,
		"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "",
	} {
		t.Setenv(key, value)
	}

	dc, err := dynamo.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := dc.UpdateVersion(ctx, "dev", "warpctl", "test", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	lv, err := dc.GetLatestVersion(ctx, "dev", "warpctl", "test")
	if err != nil {
		t.Fatal(err)
	}
	if lv != "1.0.0" {
		t.Fatalf("expected 1.0.0, got %s", lv)
	}

	key := map[string]any{"S": "dev-warpctl-test"}
	want := []request{
		{target: "DynamoDB_20120810.PutItem", body: map[string]any{
			"TableName": "deployment-blocks",
			"Item":      map[string]any{"env-service-block": key, "version": map[string]any{"S": "1.0.0"}},
		}},
		{target: "DynamoDB_20120810.GetItem", body: map[string]any{
			"TableName":      "deployment-blocks",
			"Key":            map[string]any{"env-service-block": key},
			"ConsistentRead": false,
		}},
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("requests = %+v, want %+v", requests, want)
	}
}

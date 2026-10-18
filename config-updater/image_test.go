package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the real recipe with a small, synthetic tree, never production
// config or registry publication. Opt in because Docker and network access
// for the Ubuntu/frontend images are required.
func TestConfigImageSharesCompleteTreeAcrossArchitectures(t *testing.T) {
	if os.Getenv("WARP_TEST_CONFIG_IMAGE") != "1" {
		t.Skip("set WARP_TEST_CONFIG_IMAGE=1 to run the local Docker integration test")
	}
	work := t.TempDir()
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "Dockerfile"), dockerfile, 0644); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"1.0.0/arindb/1.0.0/arin.mmdb":         []byte("historical database"),
		"1.0.0/arindb/2.0.0/arin.mmdb":         bytes.Repeat([]byte("latest database\n"), 262144),
		"1.0.0/arindb/2.0.0/arin-old.mmdb":     []byte("protected previous database"),
		"1.0.0/arindb/2.0.0/manifest.json":     []byte("latest manifest"),
		"1.0.0/arindb/2.0.0/manifest-old.json": []byte("previous manifest"),
		"1.0.0/mmdb/1.0.0/geolite2.mmdb":       []byte("geo database"),
		"1.0.0/private.yml":                    []byte("synthetic private config"),
	}
	// A directory COPY must retain archive files, as the old directory ADD
	// did; neither may unpack an archive nested inside that directory.
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "unexpected-extracted-file", Mode: 0644, Size: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("tar")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	files["1.0.0/nested.tar"] = archive.Bytes()
	for name, content := range files {
		p := filepath.Join(work, "build/main/config", name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0644)
		if strings.HasSuffix(name, "private.yml") {
			mode = 0600
		}
		if err := os.WriteFile(p, content, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		p := filepath.Join(work, "build/linux", arch, "config-updater")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("synthetic "+arch+" executable"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(work, "image.tar")
	cmd := exec.Command("docker", "--context", "desktop-linux", "buildx", "build", "--progress=plain", "--platform=linux/arm64/v8,linux/amd64", "--build-arg=warp_env=main", "--no-cache", "--provenance=false", "--output=type=oci,dest="+output, work)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("local dual-architecture build: %v\n%s", err, out)
	}
	f, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	blobs := map[string][]byte{}
	reader := tar.NewReader(f)
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		blobs[h.Name], err = io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	type descriptor struct {
		Digest   string
		Platform struct{ Architecture string }
	}
	type manifest struct {
		Manifests []descriptor
		Layers    []descriptor
	}
	decode := func(data []byte) manifest {
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	blob := func(digest string) []byte { return blobs["blobs/"+strings.Replace(digest, ":", "/", 1)] }
	index := decode(blobs["index.json"])
	// OCI exporters may wrap the architecture index in another index.
	if len(index.Manifests) == 1 {
		index = decode(blob(index.Manifests[0].Digest))
	}
	configLayer := ""
	architectures := map[string]bool{}
	for _, d := range index.Manifests {
		if d.Platform.Architecture != "amd64" && d.Platform.Architecture != "arm64" {
			continue
		}
		architectures[d.Platform.Architecture] = true
		m := decode(blob(d.Digest))
		if len(m.Layers) == 0 {
			t.Fatal("image has no layers")
		}
		last := m.Layers[len(m.Layers)-1].Digest
		if configLayer != "" && configLayer != last {
			t.Fatalf("config layer differs between architectures: %s and %s", configLayer, last)
		}
		configLayer = last
	}
	if len(architectures) != 2 {
		t.Fatalf("missing architectures: %v", architectures)
	}
	layer := blob(configLayer)
	var layerReader io.Reader = bytes.NewReader(layer)
	if len(layer) > 2 && layer[0] == 0x1f && layer[1] == 0x8b {
		gz, err := gzip.NewReader(layerReader)
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		layerReader = gz
	}
	tr := tar.NewReader(layerReader)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		rel := strings.TrimPrefix(h.Name, "root/config/")
		want, ok := files[rel]
		if !ok {
			t.Fatalf("unexpected config layer file %q", h.Name)
		}
		got, err := io.ReadAll(tr)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("content changed for %s: %v", rel, err)
		}
		mode := int64(0644)
		if strings.HasSuffix(rel, "private.yml") {
			mode = 0600
		}
		if h.Mode != mode {
			t.Fatalf("mode changed for %s: %04o, want %04o", rel, h.Mode, mode)
		}
		seen[rel] = true
	}
	if len(seen) != len(files) {
		t.Fatalf("retained %d files, want %d", len(seen), len(files))
	}
	t.Logf("both architectures share complete config layer %s (%d compressed bytes)", configLayer, len(layer))
}

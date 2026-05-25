package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDigestMissing(t *testing.T) {
	dir := t.TempDir()
	entries, err := ReadDigest(dir)
	if err != nil {
		t.Fatalf("ReadDigest on missing file: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries for missing file, got %v", entries)
	}
}

func TestReadWriteDigest(t *testing.T) {
	dir := t.TempDir()
	in := []DigestEntry{
		{Type: "SCAN", Key: "last", Value: "2026-05-25T00:00:00Z", Meta: "quick"},
		{Type: "RISK", Key: "no-circuit-breaker", Value: "HIGH:OPEN", Meta: "2026-05"},
		{Type: "ENTRYPOINT", Key: "main", Value: "cmd/server/main.go", Meta: ""},
	}
	if err := AppendDigest(dir, in); err != nil {
		t.Fatalf("AppendDigest: %v", err)
	}
	got, err := ReadDigest(dir)
	if err != nil {
		t.Fatalf("ReadDigest: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("got %d entries, want %d", len(got), len(in))
	}
	for i, e := range got {
		if e.Type != in[i].Type || e.Key != in[i].Key || e.Value != in[i].Value || e.Meta != in[i].Meta {
			t.Errorf("entry %d mismatch: got %+v, want %+v", i, e, in[i])
		}
	}
}

func TestReadDigestSkipsBlanksAndComments(t *testing.T) {
	dir := t.TempDir()
	memDir := filepath.Join(dir, ".revelara", "memory")
	if err := os.MkdirAll(memDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "# comment\n\nRISK:slug:HIGH%3AOPEN:2026-05\n\n# another comment\nSCAN:last:2026-05-25T00%3A00%3A00Z:\n"
	if err := os.WriteFile(filepath.Join(memDir, "digest.compact"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Type != "RISK" || got[0].Key != "slug" || got[0].Value != "HIGH:OPEN" {
		t.Errorf("entry 0 wrong: %+v", got[0])
	}
}

func TestURLEncodingRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Values with colons must round-trip correctly via URL encoding.
	in := []DigestEntry{
		{Type: "RISK", Key: "test-slug", Value: "CRITICAL:OPEN", Meta: "2026-05"},
	}
	if err := AppendDigest(dir, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Value != "CRITICAL:OPEN" {
		t.Errorf("value = %q, want CRITICAL:OPEN", got[0].Value)
	}
}

func TestAppendDigestRotation(t *testing.T) {
	dir := t.TempDir()
	// Fill up to maxDigestLines + 10 RISK entries, all with the same month.
	// Rotation should drop 10 oldest, leaving maxDigestLines entries.
	var first []DigestEntry
	for i := 0; i < maxDigestLines; i++ {
		first = append(first, DigestEntry{
			Type:  "RISK",
			Key:   "slug",
			Value: "HIGH:OPEN",
			Meta:  "2026-01",
		})
	}
	if err := AppendDigest(dir, first); err != nil {
		t.Fatal(err)
	}

	// Append 10 more with a later month (they should survive rotation).
	var second []DigestEntry
	for i := 0; i < 10; i++ {
		second = append(second, DigestEntry{
			Type:  "RISK",
			Key:   "newer-slug",
			Value: "MEDIUM:OPEN",
			Meta:  "2026-05",
		})
	}
	if err := AppendDigest(dir, second); err != nil {
		t.Fatal(err)
	}

	got, err := ReadDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > maxDigestLines {
		t.Errorf("got %d entries after rotation, want <= %d", len(got), maxDigestLines)
	}
	// The newer entries should be present.
	var newerCount int
	for _, e := range got {
		if e.Key == "newer-slug" {
			newerCount++
		}
	}
	if newerCount != 10 {
		t.Errorf("newer entries: got %d, want 10", newerCount)
	}
}

func TestDismissedSlugs(t *testing.T) {
	entries := []DigestEntry{
		{Type: "RISK", Key: "slug-a", Value: "HIGH:DISMISSED", Meta: "2026-05"},
		{Type: "RISK", Key: "slug-b", Value: "MEDIUM:ACCEPTED", Meta: "2026-05"},
		{Type: "RISK", Key: "slug-c", Value: "LOW:OPEN", Meta: "2026-05"},
		{Type: "SCAN", Key: "last", Value: "2026-05-25T00:00:00Z", Meta: ""},
	}
	dismissed := DismissedSlugs(entries)
	if !dismissed["slug-a"] {
		t.Error("slug-a should be dismissed")
	}
	if !dismissed["slug-b"] {
		t.Error("slug-b should be dismissed (ACCEPTED)")
	}
	if dismissed["slug-c"] {
		t.Error("slug-c should NOT be dismissed (OPEN)")
	}
}

func TestEntrypointFromDigest(t *testing.T) {
	entries := []DigestEntry{
		{Type: "SCAN", Key: "last", Value: "2026-05-25T00:00:00Z"},
		{Type: "ENTRYPOINT", Key: "main", Value: "cmd/server/main.go"},
		{Type: "RISK", Key: "slug", Value: "HIGH:OPEN", Meta: "2026-05"},
	}
	ep := EntrypointFromDigest(entries)
	if ep != "cmd/server/main.go" {
		t.Errorf("got %q, want cmd/server/main.go", ep)
	}

	// Missing entrypoint returns empty string.
	ep2 := EntrypointFromDigest(nil)
	if ep2 != "" {
		t.Errorf("got %q, want empty", ep2)
	}
}

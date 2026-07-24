package agentscan

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendAuditEventAccumulates(t *testing.T) {
	dir := initGitRepo(t)
	events := []AuditEvent{
		{Kind: AuditForceThrough, Detail: map[string]string{"mechanism": "env"}},
		{Kind: AuditForceThrough, Detail: map[string]string{"mechanism": "marker"}},
		{Kind: AuditFailOpen, Detail: map[string]string{"lens_errors": "2"}},
	}
	for _, e := range events {
		if err := AppendAuditEvent(dir, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// The log lives in the git dir.
	gitDir := filepath.Join(dir, ".git")
	data, err := os.ReadFile(filepath.Join(gitDir, AuditFileName))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var count int
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var got AuditEvent
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", count, err, line)
		}
		if got.Time.IsZero() {
			t.Errorf("event %d has zero time; AppendAuditEvent must stamp it", count)
		}
		count++
	}
	if count != 3 {
		t.Fatalf("audit log has %d events, want 3", count)
	}
}

func TestAppendAuditEventPreservesProvidedTime(t *testing.T) {
	dir := initGitRepo(t)
	when := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	if err := AppendAuditEvent(dir, AuditEvent{Time: when, Kind: AuditForceThrough}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".git", AuditFileName))
	if err != nil {
		t.Fatal(err)
	}
	var got AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Time.Equal(when) {
		t.Errorf("time = %v, want %v (provided time must be preserved)", got.Time, when)
	}
}

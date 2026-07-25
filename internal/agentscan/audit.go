package agentscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// This file is the local audit trail for gate overrides (po-66evv.6).
// Events append to rvl-audit.jsonl in the repo's git dir (per-worktree,
// never committed). The trail records force-throughs now; the fail-open
// path can reuse it, and TODO(po-66evv.11) submits these events to the
// backend when --submit is configured.

// AuditFileName is the JSONL audit log, stored in the git dir.
const AuditFileName = "rvl-audit.jsonl"

// Audit event kinds.
const (
	AuditForceThrough = "force-through"
	AuditFailOpen     = "fail-open"
)

// AuditEvent is one appended record. Time is stamped by AppendAuditEvent
// when zero. Detail carries kind-specific fields (e.g. mechanism, user).
type AuditEvent struct {
	Time   time.Time         `json:"time"`
	Kind   string            `json:"kind"`
	Detail map[string]string `json:"detail,omitempty"`
}

// AppendAuditEvent appends event as one JSON line to the audit log,
// creating the file if needed. A zero Time is stamped with time.Now().
// Best-effort durability: the caller treats a write failure as a warning,
// never a gate decision.
func AppendAuditEvent(root string, event AuditEvent) error {
	gitDir, err := resolveGitDir(root)
	if err != nil {
		return err
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	path := filepath.Join(gitDir, AuditFileName)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

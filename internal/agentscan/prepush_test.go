package agentscan

import (
	"os/exec"
	"strings"
	"testing"
)

const zeroSHA = "0000000000000000000000000000000000000000"

// initGitRepoWithHistory builds a repo on main with two commits so
// HEAD~1 and HEAD are both valid, and the second commit changes a file.
func initGitRepoWithHistory(t *testing.T) string {
	t.Helper()
	dir := initGitRepo(t)
	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "first")
	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n\nfunc A2() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "second")
	return dir
}

// revParse resolves a revision to its full sha in dir.
func revParse(t *testing.T, dir, rev string) string {
	t.Helper()
	c := exec.Command("git", "-C", dir, "rev-parse", rev)
	out, err := c.Output()
	if err != nil {
		t.Fatalf("rev-parse %s: %v", rev, err)
	}
	return strings.TrimSpace(string(out))
}

func TestParsePrePushRefs(t *testing.T) {
	in := strings.Join([]string{
		"refs/heads/main aaaa refs/heads/main bbbb",
		"", // blank line skipped
		"refs/tags/v1 cccc refs/tags/v1 " + zeroSHA,
		"garbage line", // wrong field count skipped
	}, "\n")
	refs, err := ParsePrePushRefs(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("parsed %d refs, want 2 (blank + malformed skipped)", len(refs))
	}
	if refs[0].LocalSha != "aaaa" || refs[0].RemoteSha != "bbbb" {
		t.Errorf("ref0 = %+v", refs[0])
	}
	if refs[1].RemoteRef != "refs/tags/v1" {
		t.Errorf("ref1 = %+v", refs[1])
	}
}

func TestZeroSha(t *testing.T) {
	if !zeroSha(zeroSHA) || !zeroSha("") {
		t.Error("all-zero and empty must be zero shas")
	}
	if zeroSha("abc123") {
		t.Error("non-zero sha misclassified")
	}
}

// TestResolvePrePushScansSkipsDeletesAndTags proves deletes (zero local
// sha) and tag pushes are never scanned.
func TestResolvePrePushScansSkipsDeletesAndTags(t *testing.T) {
	dir := initGitRepoWithHistory(t)
	head := revParse(t, dir, "HEAD")
	refs := []PrePushRef{
		{LocalRef: "refs/heads/del", LocalSha: zeroSHA, RemoteRef: "refs/heads/del", RemoteSha: head}, // delete
		{LocalRef: "refs/tags/v1", LocalSha: head, RemoteRef: "refs/tags/v1", RemoteSha: zeroSHA},     // tag
	}
	scans, notices := ResolvePrePushScans(dir, refs, func() (string, bool) { return "", false }, 3)
	if len(scans) != 0 {
		t.Fatalf("deletes and tags must not be scanned, got %d scans", len(scans))
	}
	if len(notices) != 2 {
		t.Errorf("expected 2 skip notices, got %v", notices)
	}
}

// TestResolvePrePushScansUsesReachableRemoteSha: a normal fast-forward
// push (remote-sha reachable) scans remoteSha...localSha.
func TestResolvePrePushScansUsesReachableRemoteSha(t *testing.T) {
	dir := initGitRepoWithHistory(t)
	base := revParse(t, dir, "HEAD~1")
	head := revParse(t, dir, "HEAD")
	refs := []PrePushRef{{
		LocalRef: "refs/heads/main", LocalSha: head,
		RemoteRef: "refs/heads/main", RemoteSha: base,
	}}
	scans, _ := ResolvePrePushScans(dir, refs, func() (string, bool) { return "", false }, 3)
	if len(scans) != 1 {
		t.Fatalf("want 1 scan, got %d", len(scans))
	}
	if scans[0].Base != base || scans[0].Sha != head {
		t.Errorf("scan = %+v, want base=%s sha=%s", scans[0], base, head)
	}
}

// TestResolvePrePushScansNewBranchUsesMergeBase: the first push of a new
// branch has an all-zero remote-sha, so the base comes from merge-base
// with the default base. This is the case nearly every PR hits.
func TestResolvePrePushScansNewBranchUsesMergeBase(t *testing.T) {
	dir := initGitRepoWithHistory(t)
	mainTip := revParse(t, dir, "HEAD")
	// Branch off and add a commit: HEAD is now ahead of main.
	gitIn(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "feature.go", "package p\n\nfunc Feat() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "feature work")
	featTip := revParse(t, dir, "HEAD")

	refs := []PrePushRef{{
		LocalRef: "refs/heads/feature", LocalSha: featTip,
		RemoteRef: "refs/heads/feature", RemoteSha: zeroSHA, // new remote branch
	}}
	// Default base resolver points at main.
	scans, notices := ResolvePrePushScans(dir, refs, func() (string, bool) { return "main", true }, 3)
	if len(scans) != 1 {
		t.Fatalf("new branch must resolve via merge-base, got %d scans; notices=%v", len(scans), notices)
	}
	if scans[0].Base != mainTip {
		t.Errorf("base = %s, want merge-base %s (main tip)", scans[0].Base, mainTip)
	}
	if scans[0].Sha != featTip {
		t.Errorf("must scan the pushed sha %s, got %s", featTip, scans[0].Sha)
	}
}

// TestResolvePrePushScansNewBranchNoBaseSkips: a new branch with no
// resolvable default base is skipped with a notice, not scanned wrong.
func TestResolvePrePushScansNewBranchNoBaseSkips(t *testing.T) {
	dir := initGitRepoWithHistory(t)
	head := revParse(t, dir, "HEAD")
	refs := []PrePushRef{{
		LocalRef: "refs/heads/orphan", LocalSha: head,
		RemoteRef: "refs/heads/orphan", RemoteSha: zeroSHA,
	}}
	scans, notices := ResolvePrePushScans(dir, refs, func() (string, bool) { return "", false }, 3)
	if len(scans) != 0 {
		t.Fatalf("unresolvable base must skip, got %d scans", len(scans))
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "cannot resolve a base") {
		t.Errorf("expected an unresolved-base notice, got %v", notices)
	}
}

// TestResolvePrePushScansDedupeAndCap.
func TestResolvePrePushScansDedupeAndCap(t *testing.T) {
	dir := initGitRepoWithHistory(t)
	base := revParse(t, dir, "HEAD~1")
	head := revParse(t, dir, "HEAD")
	// Two identical (base, sha) pairs dedupe to one.
	dup := []PrePushRef{
		{LocalRef: "a", LocalSha: head, RemoteRef: "refs/heads/a", RemoteSha: base},
		{LocalRef: "b", LocalSha: head, RemoteRef: "refs/heads/b", RemoteSha: base},
	}
	scans, _ := ResolvePrePushScans(dir, dup, func() (string, bool) { return "", false }, 3)
	if len(scans) != 1 {
		t.Errorf("identical (base,sha) must dedupe to 1, got %d", len(scans))
	}
}

// TestRangeChangeSetBetween covers the base...sha primitive and the dash
// guards on both refs.
func TestRangeChangeSetBetween(t *testing.T) {
	dir := initGitRepoWithHistory(t)
	base := revParse(t, dir, "HEAD~1")
	head := revParse(t, dir, "HEAD")
	cs, err := RangeChangeSetBetween(dir, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Files) == 0 {
		t.Errorf("expected changed files between %s and %s", base, head)
	}
	if _, err := RangeChangeSetBetween(dir, "-x", head); err == nil {
		t.Error("leading-dash base must be rejected")
	}
	if _, err := RangeChangeSetBetween(dir, base, "-y"); err == nil {
		t.Error("leading-dash head must be rejected")
	}
}

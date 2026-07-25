package agentscan

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitAllowFail runs a git command in dir, tolerating a non-zero exit
// (needed to drive a real conflicted merge, which exits 1).
func gitAllowFail(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-c", "user.email=test@example.com", "-c", "user.name=Test"}, args...)
	c := exec.Command("git", full...)
	c.Dir = dir
	_ = c.Run()
}

// stageFiles writes and stages the given path->content map.
func stageFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		writeFile(t, dir, rel, content)
	}
	gitIn(t, dir, "add", ".")
}

// synthSection builds one file's unified-diff section with n added
// lines, for budget/secret tests that do not need a real repo.
func synthSection(path string, added []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "diff --git a/%s b/%s\n", path, path)
	fmt.Fprintf(&sb, "new file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/%s\n", path)
	fmt.Fprintf(&sb, "@@ -0,0 +1,%d @@\n", len(added))
	for _, l := range added {
		fmt.Fprintf(&sb, "+%s\n", l)
	}
	return sb.String()
}

func synthLines(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("line %d", i+1)
	}
	return out
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// --- A. Generated-content filter ---

func TestFilterGeneratedBuiltinGlob(t *testing.T) {
	dir := initGitRepo(t)
	stageFiles(t, dir, map[string]string{
		"main.go":            "package main\n\nfunc main() {}\n",
		"api/openapi.gen.go": "package api\n\n// generated\nvar X = 1\n",
	})
	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cs.Diff, "openapi.gen.go") {
		t.Fatalf("fixture diff should contain generated file, got:\n%s", cs.Diff)
	}

	filtered, dropped, err := FilterGenerated(dir, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findFile(filtered, "api/openapi.gen.go"); ok {
		t.Fatal("generated file still in Files after filtering")
	}
	if _, ok := findFile(filtered, "main.go"); !ok {
		t.Fatal("non-generated file was dropped")
	}
	if strings.Contains(filtered.Diff, "openapi.gen.go") {
		t.Fatalf("generated file's diff section not stripped:\n%s", filtered.Diff)
	}
	if !strings.Contains(filtered.Diff, "main.go") {
		t.Fatalf("non-generated file's diff section was lost:\n%s", filtered.Diff)
	}
	if len(dropped) != 1 {
		t.Fatalf("expected 1 dropped file, got %d: %+v", len(dropped), dropped)
	}
	if dropped[0].Path != "api/openapi.gen.go" {
		t.Fatalf("wrong dropped path: %+v", dropped[0])
	}
	if !strings.Contains(dropped[0].Reason, "*.gen.go") {
		t.Fatalf("drop reason should name the glob, got %q", dropped[0].Reason)
	}
}

func TestFilterGeneratedGitattributes(t *testing.T) {
	dir := initGitRepo(t)
	// Committed first so the staged change set (and its diff text) holds
	// only the three content files, not .gitattributes itself.
	writeFile(t, dir, ".gitattributes",
		"schema.sql linguist-generated=true\nkeep.gen.go -linguist-generated\n")
	gitIn(t, dir, "add", ".gitattributes")
	gitIn(t, dir, "commit", "-q", "-m", "attrs")
	stageFiles(t, dir, map[string]string{
		"schema.sql":  "CREATE TABLE t (id int);\n",
		"keep.gen.go": "package p\n\nvar K = 1\n",
		"main.go":     "package main\n\nfunc main() {}\n",
	})
	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}

	filtered, dropped, err := FilterGenerated(dir, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findFile(filtered, "schema.sql"); ok {
		t.Fatal("linguist-generated=true file still in Files")
	}
	if strings.Contains(filtered.Diff, "schema.sql") {
		t.Fatal("linguist-generated file's diff section not stripped")
	}
	// An explicit -linguist-generated overrides the built-in glob:
	// .gitattributes is consulted first in the resolution order.
	if _, ok := findFile(filtered, "keep.gen.go"); !ok {
		t.Fatal("-linguist-generated file should be kept despite matching *.gen.go")
	}
	var reasons []string
	for _, d := range dropped {
		reasons = append(reasons, d.Path+": "+d.Reason)
	}
	if len(dropped) != 1 || dropped[0].Path != "schema.sql" {
		t.Fatalf("expected only schema.sql dropped, got %v", reasons)
	}
	if !strings.Contains(dropped[0].Reason, "linguist-generated") {
		t.Fatalf("drop reason should cite .gitattributes, got %q", dropped[0].Reason)
	}
}

func TestFilterGeneratedExtraGlobs(t *testing.T) {
	dir := initGitRepo(t)
	stageFiles(t, dir, map[string]string{
		"snapshots/ui.snap": "snapshot content\n",
		"main.go":           "package main\n\nfunc main() {}\n",
	})
	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}

	filtered, dropped, err := FilterGenerated(dir, cs, []string{"*.snap"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findFile(filtered, "snapshots/ui.snap"); ok {
		t.Fatal("extra-glob file still in Files")
	}
	if strings.Contains(filtered.Diff, "ui.snap") {
		t.Fatal("extra-glob file's diff section not stripped")
	}
	if len(dropped) != 1 || dropped[0].Path != "snapshots/ui.snap" {
		t.Fatalf("expected ui.snap dropped, got %+v", dropped)
	}
	if !strings.Contains(dropped[0].Reason, "*.snap") {
		t.Fatalf("drop reason should name the config glob, got %q", dropped[0].Reason)
	}
}

func TestFilterGeneratedDirGlobs(t *testing.T) {
	dir := initGitRepo(t)
	stageFiles(t, dir, map[string]string{
		"vendor/lib/lib.go":            "package lib\n",
		"frontend/node_modules/x/i.js": "module.exports = 1\n",
		"main.go":                      "package main\n\nfunc main() {}\n",
	})
	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}

	filtered, dropped, err := FilterGenerated(dir, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Files) != 1 || filtered.Files[0].Path != "main.go" {
		t.Fatalf("expected only main.go to survive, got %+v", filtered.Files)
	}
	if len(dropped) != 2 {
		t.Fatalf("expected vendor + node_modules drops, got %+v", dropped)
	}
}

// --- B. Size budget ---

func TestApplyBudgetUnderSoftPassthrough(t *testing.T) {
	cs := ChangeSet{
		Diff:     synthSection("a.go", synthLines(10)),
		Files:    []ChangedFile{{Path: "a.go", Kind: ChangeAdded}},
		BaseDesc: "staged",
	}
	res := ApplyBudget(cs, 100, 1000, 100)
	if res.FileListMode {
		t.Fatal("under-soft diff must not degrade to file-list mode")
	}
	if len(res.Chunks) != 0 {
		t.Fatalf("under-soft diff must not be chunked, got %d chunks", len(res.Chunks))
	}
	if res.ChangeSet.Diff != cs.Diff {
		t.Fatal("under-soft diff must pass through unchanged")
	}
	if len(res.Notices) != 0 {
		t.Fatalf("under-soft diff must not produce notices, got %v", res.Notices)
	}
}

func TestApplyBudgetOverSoftChunks(t *testing.T) {
	soft, hard := 50, 100000
	paths := []string{"a.go", "b.go", "c.go", "d.go", "e.go"}
	var diff strings.Builder
	var files []ChangedFile
	for _, p := range paths {
		diff.WriteString(synthSection(p, synthLines(20)))
		files = append(files, ChangedFile{Path: p, Kind: ChangeAdded})
	}
	cs := ChangeSet{Diff: diff.String(), Files: files, BaseDesc: "staged"}

	res := ApplyBudget(cs, soft, hard, 100)
	if res.FileListMode {
		t.Fatal("over-soft under-hard must chunk, not degrade")
	}
	if len(res.Chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(res.Chunks))
	}
	seen := map[string]int{}
	for i, ch := range res.Chunks {
		if n := countLines(ch.Diff); n > soft {
			t.Fatalf("chunk %d has %d lines, exceeds soft limit %d", i, n, soft)
		}
		for _, f := range ch.Files {
			seen[f.Path]++
		}
	}
	for _, p := range paths {
		if seen[p] != 1 {
			t.Fatalf("file %s covered %d times across chunks, want exactly 1", p, seen[p])
		}
	}
	if len(seen) != len(paths) {
		t.Fatalf("chunks cover %d files, want %d", len(seen), len(paths))
	}
	if len(res.Notices) == 0 {
		t.Fatal("chunking must produce a notice (no silent caps)")
	}
}

func TestApplyBudgetGiantFileOwnChunk(t *testing.T) {
	soft, hard := 50, 100000
	giant := synthSection("giant.go", synthLines(80))
	small := synthSection("small.go", synthLines(5))
	cs := ChangeSet{
		Diff: giant + small,
		Files: []ChangedFile{
			{Path: "giant.go", Kind: ChangeAdded},
			{Path: "small.go", Kind: ChangeAdded},
		},
		BaseDesc: "staged",
	}

	res := ApplyBudget(cs, soft, hard, 100)
	if res.FileListMode {
		t.Fatal("must chunk, not degrade")
	}
	var giantChunk *ChangeSet
	for i := range res.Chunks {
		for _, f := range res.Chunks[i].Files {
			if f.Path == "giant.go" {
				giantChunk = &res.Chunks[i]
			}
		}
	}
	if giantChunk == nil {
		t.Fatal("giant.go missing from chunks")
	}
	if len(giantChunk.Files) != 1 {
		t.Fatalf("oversized file must get its own chunk, shares with %+v", giantChunk.Files)
	}
	if len(res.Notices) == 0 {
		t.Fatal("oversized single file must produce a notice")
	}
}

func TestApplyBudgetOverHardFileListMode(t *testing.T) {
	soft, hard := 50, 100
	cs := ChangeSet{
		Diff: synthSection("big.go", synthLines(200)),
		Files: []ChangedFile{
			{Path: "big.go", Kind: ChangeAdded},
		},
		BaseDesc: "staged",
	}

	res := ApplyBudget(cs, soft, hard, 100)
	if !res.FileListMode {
		t.Fatal("over-hard diff must degrade to file-list mode")
	}
	if len(res.Chunks) != 0 {
		t.Fatal("file-list mode must not also produce chunks")
	}
	if len(res.ChangeSet.Files) != 1 {
		t.Fatal("file-list mode must keep Files")
	}
	if strings.Contains(res.ChangeSet.Diff, "+line 1") {
		t.Fatal("file-list mode must not carry diff content")
	}
	if !strings.Contains(res.ChangeSet.Diff, "big.go") {
		t.Fatal("file-list summary must name the changed files")
	}
	if len(res.Notices) == 0 {
		t.Fatal("file-list degrade must produce a loud notice")
	}
	joined := strings.ToLower(strings.Join(res.Notices, "\n"))
	if !strings.Contains(joined, "not") || !strings.Contains(joined, "file") {
		t.Fatalf("notice must loudly explain the degrade, got %v", res.Notices)
	}
}

func TestApplyBudgetDefaults(t *testing.T) {
	if DefaultSoftLimitLines != 1500 || DefaultHardLimitLines != 6000 {
		t.Fatalf("default limits changed: soft=%d hard=%d", DefaultSoftLimitLines, DefaultHardLimitLines)
	}
	if DefaultChunkMaxFiles != 4 {
		t.Fatalf("default chunk-max-files changed: %d", DefaultChunkMaxFiles)
	}
	cs := ChangeSet{
		Diff:  synthSection("a.go", synthLines(10)),
		Files: []ChangedFile{{Path: "a.go", Kind: ChangeAdded}},
	}
	// Non-positive limits fall back to the defaults.
	res := ApplyBudget(cs, 0, 0, 0)
	if res.FileListMode || len(res.Chunks) != 0 {
		t.Fatal("small diff with default limits must pass through")
	}
}

// Many tiny files, well under the soft LINE limit but over the file cap,
// must still chunk: per-lens runtime scales with file count, not lines.
func TestApplyBudgetManyFilesUnderSoftChunks(t *testing.T) {
	soft, hard, maxFiles := 100000, 200000, 3
	var diff strings.Builder
	var files []ChangedFile
	for i := 0; i < 7; i++ {
		p := fmt.Sprintf("f%d.go", i)
		diff.WriteString(synthSection(p, synthLines(3)))
		files = append(files, ChangedFile{Path: p, Kind: ChangeAdded})
	}
	cs := ChangeSet{Diff: diff.String(), Files: files, BaseDesc: "staged"}

	res := ApplyBudget(cs, soft, hard, maxFiles)
	if res.FileListMode {
		t.Fatal("under-soft many-file diff must chunk, not degrade")
	}
	if len(res.Chunks) != 3 { // ceil(7/3)
		t.Fatalf("7 files at max %d/chunk = 3 chunks, got %d", maxFiles, len(res.Chunks))
	}
	seen := map[string]int{}
	for i, ch := range res.Chunks {
		if len(ch.Files) > maxFiles {
			t.Fatalf("chunk %d has %d files, over cap %d", i, len(ch.Files), maxFiles)
		}
		for _, f := range ch.Files {
			seen[f.Path]++
		}
	}
	if len(seen) != 7 {
		t.Fatalf("chunks cover %d files, want 7", len(seen))
	}
	for p, n := range seen {
		if n != 1 {
			t.Fatalf("file %s covered %d times, want exactly 1", p, n)
		}
	}
	if len(res.Notices) == 0 {
		t.Fatal("file-count chunking must produce a notice (no silent split)")
	}
}

// A change with exactly the file cap, under the soft limit, must NOT chunk.
func TestApplyBudgetAtFileCapPassthrough(t *testing.T) {
	maxFiles := 4
	var diff strings.Builder
	var files []ChangedFile
	for i := 0; i < maxFiles; i++ {
		p := fmt.Sprintf("f%d.go", i)
		diff.WriteString(synthSection(p, synthLines(3)))
		files = append(files, ChangedFile{Path: p, Kind: ChangeAdded})
	}
	cs := ChangeSet{Diff: diff.String(), Files: files, BaseDesc: "staged"}

	res := ApplyBudget(cs, 100000, 200000, maxFiles)
	if res.FileListMode {
		t.Fatal("at-cap under-soft diff must not degrade")
	}
	if len(res.Chunks) != 0 {
		t.Fatalf("files == cap must pass through unchunked, got %d chunks", len(res.Chunks))
	}
	if len(res.Notices) != 0 {
		t.Fatalf("passthrough must not produce notices, got %v", res.Notices)
	}
}

// --- C. Secret refusal ---

func TestCheckSecretsDetectsEachPatternClass(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		secret string // substring that must NOT appear in the error
	}{
		{"aws-access-key-id", `aws_key = "AKIAIOSFODNN7EXAMPLE"`, "AKIAIOSFODNN7EXAMPLE"},
		{"private-key-block", `-----BEGIN RSA PRIVATE KEY-----`, "BEGIN RSA PRIVATE KEY"},
		{"generic-assignment", `api_key = "hunter2hunter2hunter2"`, "hunter2hunter2hunter2"},
		{"jwt", `token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"`, "eyJhbGciOiJIUzI1NiJ9"},
		{"slack-token", `slack = "xoxb-123456789012-abcdefghijkl"`, "xoxb-123456789012-abcdefghijkl"},
		{"github-token", `gh = "ghp_abcdefghijklmnopqrstuvwxyz012345"`, "ghp_abcdefghijklmnopqrstuvwxyz012345"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := ChangeSet{
				Diff: synthSection("cfg/app.go", []string{"package cfg", tc.line, "// end"}),
				Files: []ChangedFile{
					{Path: "cfg/app.go", Kind: ChangeAdded},
				},
			}
			err := CheckSecrets(cs)
			if err == nil {
				t.Fatalf("secret not detected in %q", tc.line)
			}
			if !errors.Is(err, ErrSecretsDetected) {
				t.Fatalf("error should wrap ErrSecretsDetected, got %v", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "cfg/app.go") {
				t.Fatalf("error must name the file, got %q", msg)
			}
			// The secret is on the 2nd added line of the hunk.
			if !strings.Contains(msg, "cfg/app.go:2") {
				t.Fatalf("error must include file:line, got %q", msg)
			}
			if strings.Contains(msg, tc.secret) {
				t.Fatalf("error text echoes the secret value: %q", msg)
			}
			var se *SecretsError
			if !errors.As(err, &se) {
				t.Fatalf("error should be a *SecretsError, got %T", err)
			}
			if len(se.Hits) == 0 || se.Hits[0].Path != "cfg/app.go" || se.Hits[0].Line != 2 {
				t.Fatalf("wrong hit location: %+v", se.Hits)
			}
		})
	}
}

func TestCheckSecretsCleanDiff(t *testing.T) {
	cs := ChangeSet{
		Diff: synthSection("main.go", []string{
			"package main",
			`func main() { fmt.Println("hello") }`,
			"// TODO: rotate the password prompt copy", // word alone must not trip
		}),
		Files: []ChangedFile{{Path: "main.go", Kind: ChangeAdded}},
	}
	if err := CheckSecrets(cs); err != nil {
		t.Fatalf("clean diff must pass, got %v", err)
	}
}

// --- D. Skip states ---

func TestSkipReasonCleanRepo(t *testing.T) {
	dir := initGitRepo(t)
	if reason, skip := SkipReason(dir); skip {
		t.Fatalf("clean repo must not skip, got reason %q", reason)
	}
}

func TestSkipReasonMergeInProgress(t *testing.T) {
	dir := initGitRepo(t)
	// Conflicting add of f.txt on two branches, then a real merge.
	writeFile(t, dir, "f.txt", "main version\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "main f")
	gitIn(t, dir, "checkout", "-q", "-b", "side", "HEAD~1")
	writeFile(t, dir, "f.txt", "side version\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "side f")
	gitIn(t, dir, "checkout", "-q", "main")
	gitAllowFail(t, dir, "merge", "side") // conflicts; leaves MERGE_HEAD
	if _, err := os.Stat(filepath.Join(dir, ".git", "MERGE_HEAD")); err != nil {
		t.Fatalf("fixture did not produce a merge in progress: %v", err)
	}

	reason, skip := SkipReason(dir)
	if !skip {
		t.Fatal("mid-merge repo must skip")
	}
	if !strings.Contains(reason, "merge") {
		t.Fatalf("reason should mention merge, got %q", reason)
	}
}

// Rebase and cherry-pick states are simulated by creating the state
// marker inside the resolved git dir (driving a real interactive rebase
// from a test is impractical); the markers are exactly what git itself
// creates (rebase-merge/ dir, CHERRY_PICK_HEAD file).
func TestSkipReasonRebaseInProgress(t *testing.T) {
	dir := initGitRepo(t)
	if err := os.MkdirAll(filepath.Join(dir, ".git", "rebase-merge"), 0o755); err != nil {
		t.Fatal(err)
	}
	reason, skip := SkipReason(dir)
	if !skip || !strings.Contains(reason, "rebase") {
		t.Fatalf("rebase state not detected: skip=%v reason=%q", skip, reason)
	}
}

func TestSkipReasonCherryPickInProgress(t *testing.T) {
	dir := initGitRepo(t)
	if err := os.WriteFile(filepath.Join(dir, ".git", "CHERRY_PICK_HEAD"),
		[]byte("0123456789012345678901234567890123456789\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reason, skip := SkipReason(dir)
	if !skip || !strings.Contains(reason, "cherry-pick") {
		t.Fatalf("cherry-pick state not detected: skip=%v reason=%q", skip, reason)
	}
}

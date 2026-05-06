package scanner

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "--allow-empty", "-q", "-m", "init"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestResolveBaseRefFromFlagWins(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root:        dir,
		FlagBaseRef: "main",
		Env:         map[string]string{"RVL_BASE_REF": "feature/x"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref != "main" {
		t.Errorf("got %q, want main", res.Ref)
	}
	if res.Source != BaseRefFromFlag {
		t.Errorf("source=%q, want flag", res.Source)
	}
}

func TestResolveBaseRefFromRVLEnv(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root: dir,
		Env:  map[string]string{"RVL_BASE_REF": "main"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != BaseRefFromRVLEnv {
		t.Errorf("source=%q, want RVL_BASE_REF", res.Source)
	}
}

func TestResolveBaseRefFromGitHub(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root: dir,
		Env:  map[string]string{"GITHUB_BASE_REF": "main"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != BaseRefFromGitHub {
		t.Errorf("source=%q, want GITHUB_BASE_REF", res.Source)
	}
}

func TestResolveBaseRefHardFailsWhenAllMissing(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{Root: dir}
	res, err := ResolveBaseRef(cfg)
	if !errors.Is(err, ErrNoBaseRef) {
		t.Fatalf("got err=%v, want ErrNoBaseRef", err)
	}
	if res.Ref != "" {
		t.Errorf("expected empty Ref, got %q", res.Ref)
	}
	msg := FormatNoBaseRefDiagnostic(res)
	if !strings.Contains(msg, "Tried") {
		t.Errorf("diagnostic missing 'Tried' summary: %s", msg)
	}
	if !strings.Contains(msg, "--scan-all-on-missing-base") {
		t.Errorf("diagnostic missing the opt-in flag mention: %s", msg)
	}
}

func TestResolveBaseRefSkipsUnreachableThenContinues(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root:        dir,
		FlagBaseRef: "no-such-ref",
		Env:         map[string]string{"RVL_BASE_REF": "main"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != BaseRefFromRVLEnv {
		t.Errorf("source=%q, want RVL_BASE_REF after flag was unreachable", res.Source)
	}
}

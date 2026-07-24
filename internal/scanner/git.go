package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// BaseRefSource is the resolution chain order, used for diagnostics.
type BaseRefSource string

const (
	BaseRefFromFlag      BaseRefSource = "--base flag"
	BaseRefFromRVLEnv    BaseRefSource = "RVL_BASE_REF env var"
	BaseRefFromGitHub    BaseRefSource = "GITHUB_BASE_REF env var (PR events)"
	BaseRefFromGitLab    BaseRefSource = "CI_MERGE_REQUEST_TARGET_BRANCH_NAME env var"
	BaseRefFromConfig    BaseRefSource = ".revelara.yaml scanner.base_ref"
	BaseRefSourceUnknown BaseRefSource = "unknown"
)

// BaseRefResolution captures what the resolver chose, why, and which
// fallbacks it tried before that. Used by --changed-only for both the
// diff and the diagnostic message on resolution failure.
type BaseRefResolution struct {
	Ref     string        // empty if nothing reachable
	Source  BaseRefSource // which step in the chain matched
	Tried   []BaseRefSource
	Missing []BaseRefSource
}

// ErrNoBaseRef is returned by ResolveBaseRef when no source produces a
// reachable ref. The error embeds a BaseRefResolution so the caller
// can render the PRD's diagnostic message verbatim.
var ErrNoBaseRef = errors.New("no reachable base ref")

// ChangedOnlyConfig is the input for --changed-only resolution.
type ChangedOnlyConfig struct {
	Root         string // git working tree root
	FlagBaseRef  string // value of --base, if any
	YAMLBaseRef  string // .revelara.yaml scanner.base_ref, if any (po-fayz.12)
	Env          map[string]string
}

// ResolveBaseRef walks the PRD-defined resolution chain and returns
// the first reachable base ref. Resolution stops at the first source
// that yields a non-empty value AND the ref is reachable in the local
// repo (verified via `git rev-parse --verify`).
func ResolveBaseRef(cfg ChangedOnlyConfig) (BaseRefResolution, error) {
	if cfg.Env == nil {
		cfg.Env = make(map[string]string)
	}
	chain := []struct {
		source BaseRefSource
		value  string
	}{
		{BaseRefFromFlag, strings.TrimSpace(cfg.FlagBaseRef)},
		{BaseRefFromRVLEnv, strings.TrimSpace(cfg.Env["RVL_BASE_REF"])},
		{BaseRefFromGitHub, strings.TrimSpace(cfg.Env["GITHUB_BASE_REF"])},
		{BaseRefFromGitLab, strings.TrimSpace(cfg.Env["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"])},
		{BaseRefFromConfig, strings.TrimSpace(cfg.YAMLBaseRef)},
	}
	res := BaseRefResolution{}
	for _, step := range chain {
		res.Tried = append(res.Tried, step.source)
		if step.value == "" {
			res.Missing = append(res.Missing, step.source)
			continue
		}
		if !gitRefReachable(cfg.Root, step.value) {
			// Try common transforms: a bare branch name may need an
			// origin/ prefix in shallow clones.
			if !strings.HasPrefix(step.value, "origin/") && gitRefReachable(cfg.Root, "origin/"+step.value) {
				res.Ref = "origin/" + step.value
				res.Source = step.source
				return res, nil
			}
			res.Missing = append(res.Missing, step.source)
			continue
		}
		res.Ref = step.value
		res.Source = step.source
		return res, nil
	}
	return res, ErrNoBaseRef
}

// FormatNoBaseRefDiagnostic renders the PRD's user-facing diagnostic
// when no base ref is reachable.
func FormatNoBaseRefDiagnostic(res BaseRefResolution) string {
	var sb strings.Builder
	sb.WriteString("error: --changed-only requires a reachable base ref, but none was found.\n")
	sb.WriteString("  Tried:")
	for i, src := range res.Tried {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, " %s", src)
	}
	sb.WriteString("\n")
	sb.WriteString("  Fix: set fetch-depth: 0 in your checkout step, or pass --base <ref> explicitly.\n")
	sb.WriteString("  Or:  pass --scan-all-on-missing-base to fall back to a full scan.\n")
	return sb.String()
}

// ResolveChangedFiles returns relative file paths (forward-slash) that
// have changed between baseRef and HEAD. Returns nil with no error if
// baseRef is empty (caller signals "scan everything"). When baseRef is
// set and the diff is genuinely empty, returns a non-nil empty slice so
// callers can distinguish "no changes" (scan nothing) from "no base"
// (scan everything). The result is suitable for ScanOptions.OnlyFiles.
//
// po-t8acf: the revision range must precede `--`; with the range after
// `--`, git parses it as a pathspec and the diff is silently empty.
func ResolveChangedFiles(root, baseRef string) ([]string, error) {
	if baseRef == "" {
		return nil, nil
	}
	if strings.HasPrefix(baseRef, "-") {
		return nil, fmt.Errorf("invalid base ref %q: leading dash", baseRef)
	}
	cmd := exec.Command("git", "-C", root, "diff", "--name-only", baseRef+"...HEAD", "--")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff against %s: %w", baseRef, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	files := []string{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		files = append(files, NormalizePath(l))
	}
	return files, nil
}

// gitRefReachable reports whether ref resolves to a commit in root's
// local repository (i.e., `git rev-parse --verify --quiet <ref>` exits
// cleanly).
func gitRefReachable(root, ref string) bool {
	if strings.HasPrefix(ref, "-") {
		return false
	}
	cmd := exec.Command("git", "-C", root, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

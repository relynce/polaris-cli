package agentscan

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// This file implements the pre-push protocol (po-66evv.9). A git
// pre-push hook receives, on stdin, one line per pushed ref:
//
//	<local-ref> SP <local-sha> SP <remote-ref> SP <remote-sha> LF
//
// The red-team flagged that anchoring the scan to HEAD (as a naive
// base...HEAD would) is wrong: the pushed ref may not be the checked-out
// branch, the first push of a new branch has an all-zero remote-sha, and
// tag/delete pushes must not be gated. This resolves each pushed ref to
// a concrete base...sha range instead.

// zeroSha reports whether s is git's all-zero object id (a deleted ref
// on the local side, or an absent remote ref). Handles both SHA-1 (40)
// and SHA-256 (64) widths by checking for all zeros of any length.
func zeroSha(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	for _, r := range s {
		if r != '0' {
			return false
		}
	}
	return true
}

// PrePushRef is one parsed stdin line from a pre-push hook.
type PrePushRef struct {
	LocalRef  string
	LocalSha  string
	RemoteRef string
	RemoteSha string
}

// ParsePrePushRefs parses the githooks(5) pre-push stdin lines. Malformed
// lines are skipped (git only ever emits the 4-field form; anything else
// is not ours to gate on).
func ParsePrePushRefs(r io.Reader) ([]PrePushRef, error) {
	var refs []PrePushRef
	sc := bufio.NewScanner(r)
	// A ref line is short; the default 64KB buffer is ample.
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 4 {
			continue
		}
		refs = append(refs, PrePushRef{
			LocalRef:  f[0],
			LocalSha:  f[1],
			RemoteRef: f[2],
			RemoteSha: f[3],
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read pre-push stdin: %w", err)
	}
	return refs, nil
}

// PrePushScan is one resolved range to scan: everything reachable from
// Sha but not from Base. Ref is the pushed local ref, for reporting.
type PrePushScan struct {
	Ref  string
	Base string
	Sha  string
}

// RefReachable reports whether ref resolves to a commit in root's local
// repository. Exported for the CLI's default-base fallback (po-66evv.9).
func RefReachable(root, ref string) bool {
	return gitReachable(root, ref)
}

// gitReachable reports whether sha resolves to a commit in root.
func gitReachable(root, sha string) bool {
	if sha == "" || strings.HasPrefix(sha, "-") {
		return false
	}
	_, err := runGit(root, "rev-parse", "--verify", "--quiet", sha+"^{commit}")
	return err == nil
}

// mergeBase returns the merge base of a and b, or "" if none.
func mergeBase(root, a, b string) string {
	out, err := runGit(root, "merge-base", a, b)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// DefaultBaseFunc resolves a fallback base ref (e.g. origin/main) when a
// pushed ref has no usable remote-sha. It returns the ref and whether one
// was found.
type DefaultBaseFunc func() (string, bool)

// ResolvePrePushScans turns parsed ref lines into concrete scans,
// applying the protocol rules:
//
//   - Skip deletes (zero local-sha): nothing to scan.
//   - Skip refs/tags/*: a tag points at already-scanned commits, and for
//     some workflows a tag push is a production deploy that must not be
//     gated or re-diffed.
//   - Base = remote-sha when non-zero AND locally reachable (handles the
//     normal fast-forward and, via three-dot, force-push-after-rebase).
//     Otherwise merge-base(local-sha, default-base); the default base is
//     the caller's resolver (config chain, else origin/HEAD).
//   - Scan the pushed local-sha, never HEAD.
//   - Dedupe identical (base, sha) pairs.
//   - Cap the number of scans at maxRefs (a loud notice lists the drop),
//     so `git push --all` cannot fan out unbounded agent runs.
//
// Returns the scans and any human notices (skips, cap, unresolved base).
func ResolvePrePushScans(root string, refs []PrePushRef, defaultBase DefaultBaseFunc, maxRefs int) ([]PrePushScan, []string) {
	if maxRefs <= 0 {
		maxRefs = DefaultMaxPrePushRefs
	}
	var scans []PrePushScan
	var notices []string
	seen := map[string]bool{}

	for _, ref := range refs {
		if zeroSha(ref.LocalSha) {
			notices = append(notices, fmt.Sprintf("skipping deleted ref %s", ref.RemoteRef))
			continue
		}
		if strings.HasPrefix(ref.RemoteRef, "refs/tags/") {
			notices = append(notices, fmt.Sprintf("skipping tag push %s", ref.RemoteRef))
			continue
		}

		base := ""
		if !zeroSha(ref.RemoteSha) && gitReachable(root, ref.RemoteSha) {
			base = ref.RemoteSha
		} else if db, ok := defaultBase(); ok {
			if mb := mergeBase(root, ref.LocalSha, db); mb != "" {
				base = mb
			}
		}
		if base == "" {
			notices = append(notices, fmt.Sprintf(
				"cannot resolve a base for %s (new branch with no local base ref); skipping - set scanner.base_ref or push after fetching the target",
				ref.LocalRef))
			continue
		}

		key := base + ".." + ref.LocalSha
		if seen[key] {
			continue
		}
		seen[key] = true
		scans = append(scans, PrePushScan{Ref: ref.LocalRef, Base: base, Sha: ref.LocalSha})
	}

	if len(scans) > maxRefs {
		notices = append(notices, fmt.Sprintf(
			"pushing %d refs; scanning the first %d (cap), skipping %d",
			len(scans), maxRefs, len(scans)-maxRefs))
		scans = scans[:maxRefs]
	}
	return scans, notices
}

package matchers

import (
	"regexp"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// mutableTags is the curated set of tag values that signal a rolling /
// mutable image reference. Pinned tags (e.g. v1.2.3, 7.4.2-alpine,
// 2025-04-01, sha-abc1234) are intentionally absent.
//
// Conservative starter set: explicit rolling channels (latest, edge,
// nightly, rolling, unstable), branch refs (main, master, develop,
// dev), channel refs (stable), and distribution-only tags that roll
// within their channel (alpine, slim).
//
// Distro codename tags (jammy, bookworm, focal, etc.) are NOT included
// — they pin the major release while rolling patches, similar to how
// "7.4-alpine" or "1.22-alpine" pin a minor version. Including them
// would flag a common and intentional pinning pattern.
var mutableTags = map[string]bool{
	"latest":   true,
	"edge":     true,
	"nightly":  true,
	"rolling":  true,
	"unstable": true,
	"stable":   true,
	"main":     true,
	"master":   true,
	"develop":  true,
	"dev":      true,
	"alpine":   true,
	"slim":     true,
}

func isMutableTag(tag string) bool {
	return mutableTags[tag]
}

// isMutableImageReference reports whether an image reference like
// "redis", "redis:alpine", or "registry.io:port/repo/img:tag" is
// mutable — subject to silent change at the registry between pulls.
//
// Digest pins (@sha256:...) always count as immutable, regardless of
// any tag. References with no tag are treated as implicit :latest.
func isMutableImageReference(ref string) bool {
	// Digest pin: immutable.
	if strings.Contains(ref, "@") {
		return false
	}
	// Find the tag: look at the substring after the last "/" so that a
	// registry "host:port" prefix isn't confused for a tag separator.
	afterSlash := ref
	if idx := strings.LastIndex(ref, "/"); idx >= 0 {
		afterSlash = ref[idx+1:]
	}
	_, tag, hasColon := strings.Cut(afterSlash, ":")
	if !hasColon {
		// No tag — implicit :latest → mutable.
		return true
	}
	return isMutableTag(tag)
}

// k8sImageLineRE matches a Kubernetes YAML `image:` field line and
// captures the value. Accepts an optional list-item dash prefix so
// inline forms like `- image: foo` are matched alongside the indented
// `  image: foo` form.
//
// Note: this matches `image:` in any YAML schema that uses that field.
// Skaffold's `skaffold.yaml` uses the same syntax for build artifact
// declarations (which aren't deployed image references), so the
// matcher's ExcludePatterns filter that file out.
var k8sImageLineRE = regexp.MustCompile(`(?m)^\s+(?:-\s+)?image:\s+(\S+)\s*$`)

// k8sMutableImageTag flags Kubernetes container image references that
// are mutable (no digest pin, tag is implicit :latest or in the
// curated mutable-tag set). Skips Helm template substitution and any
// reference whose tag is a specific version or includes an @sha256
// digest.
func k8sMutableImageTag() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		var out []scanner.Candidate
		text := string(src)
		for _, m := range k8sImageLineRE.FindAllStringSubmatchIndex(text, -1) {
			lineText := text[m[0]:m[1]]
			ref := text[m[2]:m[3]]
			// Skip Helm / template-engine substitution.
			if strings.Contains(lineText, "{{") {
				continue
			}
			if !isMutableImageReference(ref) {
				continue
			}
			out = append(out, scanner.Candidate{
				Slug:        "k8s-mutable-image-tag",
				File:        relPath,
				LineNumber:  lineOf(text, m[0]),
				Snippet:     "image " + ref + " is not pinned (no digest, mutable tag)",
				Description: "Kubernetes manifest references an image without a digest pin",
				ImageRef:    ref,
			})
		}
		return out
	}
	return scanner.Matcher{
		Slug:            "k8s-mutable-image-tag",
		Description:     "Kubernetes manifest image without digest pin",
		Category:        "change_management",
		ControlCodes:    []string{"RC-014"},
		FilePatterns:    []string{"**/*.yaml", "**/*.yml"},
		ExcludePatterns: []string{"skaffold*.yaml", "skaffold*.yml", "**/skaffold*.yaml", "**/skaffold*.yml"},
		Confidence:      "high",
		Severity:        "high",
		Impl:            scanner.ImplHeuristic,
		Source:          "curated",
		Check:           check,
		Provenance: scanner.Provenance{
			FailureDescription: "Unpinned image references can be silently replaced at the registry, breaking rollback determinism and opening a supply-chain substitution vector",
			IncidentFrequency:  "Common in clusters where deploys appear identical but pull different image content",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "minutes once detected; hours when root cause is unclear",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-014", "RC-041"},
		},
		// Rollup per image ref so the same image referenced in multiple
		// manifests (e.g., base and overlay both list backend:v3.2.1)
		// collapses into one Finding.
		RollupKey: scanner.RollupByImageRef,
	}
}

// dockerfileFROMRE matches a Dockerfile FROM instruction (case-insensitive),
// optionally consumes a leading `--platform=...` flag, captures the image
// reference, and optionally captures the AS <stage> name.
//
// Group 1: image reference. Group 2: stage name (empty if absent).
var dockerfileFROMRE = regexp.MustCompile(`(?im)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)

// dockerfileMutableBaseImage flags Dockerfile FROM references that are
// mutable. Skips:
//   - "FROM scratch" (the empty base; nothing to pin)
//   - build-arg substitution like `FROM $BASE` or `FROM ${BASE}` (the
//     pinning decision is runtime, not static)
//   - references to a multi-stage AS name defined earlier in the same
//     Dockerfile (those reuse a local stage, not a registry image)
func dockerfileMutableBaseImage() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		text := string(src)
		matches := dockerfileFROMRE.FindAllStringSubmatchIndex(text, -1)

		// First pass: collect all stage names defined via `AS <name>` so
		// the second pass can skip later FROM lines that reference them.
		stages := map[string]bool{}
		for _, m := range matches {
			if m[4] >= 0 && m[5] >= 0 {
				stages[text[m[4]:m[5]]] = true
			}
		}

		var out []scanner.Candidate
		for _, m := range matches {
			ref := text[m[2]:m[3]]
			if ref == "scratch" {
				continue
			}
			if strings.Contains(ref, "$") {
				continue
			}
			if stages[ref] {
				// Multi-stage reference, not a registry image.
				continue
			}
			if !isMutableImageReference(ref) {
				continue
			}
			out = append(out, scanner.Candidate{
				Slug:        "dockerfile-mutable-base-image",
				File:        relPath,
				LineNumber:  lineOf(text, m[0]),
				Snippet:     "FROM " + ref + " is not pinned (no digest, mutable tag)",
				Description: "Dockerfile FROM without digest pin",
			})
		}
		return out
	}
	return scanner.Matcher{
		Slug:         "dockerfile-mutable-base-image",
		Description:  "Dockerfile FROM without digest pin",
		Category:     "change_management",
		ControlCodes: []string{"RC-014"},
		FilePatterns: []string{"Dockerfile", "Dockerfile.*", "**/Dockerfile", "**/Dockerfile.*"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         scanner.ImplHeuristic,
		Source:       "curated",
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Base image without digest pin can be silently substituted at the registry, allowing supply-chain compromise to land in the build without a Git diff",
			IncidentFrequency:  "Recurrent in supply-chain audit gaps",
			TypicalBlastRadius: "service-level to organization-level when a base image is shared across many services",
			TypicalMTTR:        "varies; detection is often delayed",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-014", "RC-041"},
		},
	}
}

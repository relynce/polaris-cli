package commands

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/revelara-ai/rvl-cli/internal/project"
)

// This file implements the team side of `rvl scan` (po-77b6w.1,
// org-ownership spec Decisions 1-2):
//
//   - applyTeamAssignments: carries .revelara.yaml `team:` values (repo
//     default + per-component) on the scan submission; `--team=<slug>`
//     overrides the whole submission (bootstrap path for horizontal
//     engineers scanning repos they cannot commit to).
//   - warnUnknownTeams: pre-submit did-you-mean against the org's known
//     team slugs (GET /api/v1/teams/slugs). Loud, NEVER blocking: agents
//     must be able to run headless, and creating a new team on first
//     sight is legitimate.

// applyTeamAssignments resolves the team fields on the scan request.
// Precedence: --team override > .revelara.yaml. The override applies to
// the WHOLE submission (repo default and components alike), so component
// teams are dropped when it is set.
func applyTeamAssignments(scanReq *ScanRequest, projectCfg *project.ProjectConfig, teamOverride string) {
	if teamOverride != "" {
		scanReq.Team = teamOverride
		scanReq.TeamSource = "override"
		scanReq.ComponentTeams = nil
		return
	}
	if projectCfg == nil {
		return
	}
	if projectCfg.Team != "" {
		scanReq.Team = projectCfg.Team
	}
	for _, c := range projectCfg.Components {
		if c.Name == "" || c.Team == "" {
			continue
		}
		if scanReq.ComponentTeams == nil {
			scanReq.ComponentTeams = make(map[string]string)
		}
		scanReq.ComponentTeams[c.Name] = c.Team
	}
}

// slugifyTeamPreview mirrors the polaris server-side slugify
// (internal/api/team_registry_handlers.go slugifyTeamName): lowercase,
// trim, whitespace/underscore runs -> hyphens, invalid characters dropped,
// hyphen runs collapsed, 2..63 chars. Used only for the did-you-mean
// preview; the server remains authoritative.
func slugifyTeamPreview(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) || r == '_' || r == '-':
			b.WriteByte('-')
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	s = b.String()
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	if len(s) < 2 {
		return ""
	}
	return s
}

// scanRequestTeams returns the distinct team values carried on the
// request, in deterministic order (repo-level first).
func scanRequestTeams(scanReq *ScanRequest) []string {
	seen := make(map[string]bool)
	var teams []string
	add := func(team string) {
		if team != "" && !seen[team] {
			seen[team] = true
			teams = append(teams, team)
		}
	}
	add(scanReq.Team)
	names := make([]string, 0, len(scanReq.ComponentTeams))
	for name := range scanReq.ComponentTeams {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		add(scanReq.ComponentTeams[name])
	}
	return teams
}

// levenshtein returns the edit distance between two strings. Small inputs
// only (team slugs), so the simple O(len(a)*len(b)) DP is fine.
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := 0; j <= len(br); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(br)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// nearestSlugs returns up to max known slugs closest to target: prefix
// matches first, then slugs within edit distance 3, ordered by distance.
func nearestSlugs(target string, known []string, max int) []string {
	type cand struct {
		slug string
		dist int
	}
	var cands []cand
	for _, k := range known {
		if k == target {
			continue
		}
		d := levenshtein(target, k)
		if strings.HasPrefix(k, target) || strings.HasPrefix(target, k) {
			d = 0 // prefix relationship ranks first
		}
		if d <= 3 {
			cands = append(cands, cand{slug: k, dist: d})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].dist < cands[j].dist })
	var out []string
	for _, c := range cands {
		out = append(out, c.slug)
		if len(out) == max {
			break
		}
	}
	return out
}

// warnUnknownTeams prints a did-you-mean warning for every team value on
// the request whose slugified preview is not among the org's known slugs.
// knownSlugs == nil means the lookup failed (offline, old server) and the
// check is skipped entirely. Never blocks, never changes the request.
func warnUnknownTeams(out io.Writer, knownSlugs []string, scanReq *ScanRequest) {
	if knownSlugs == nil {
		return
	}
	known := make(map[string]bool, len(knownSlugs))
	for _, s := range knownSlugs {
		known[s] = true
	}
	for _, team := range scanRequestTeams(scanReq) {
		slug := slugifyTeamPreview(team)
		if slug == "" {
			fmt.Fprintf(out, "Warning: team %q slugifies to nothing usable and will be ignored by the server.\n", team)
			continue
		}
		if known[slug] {
			continue
		}
		msg := fmt.Sprintf("Warning: team %q (slug %q) is not a known team in your organization", team, slug)
		if near := nearestSlugs(slug, knownSlugs, 3); len(near) > 0 {
			msg += "; nearest known: " + strings.Join(near, ", ")
		}
		msg += ". Proceeding creates a new team."
		fmt.Fprintln(out, msg)
	}
}

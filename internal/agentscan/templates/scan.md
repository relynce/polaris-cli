# Reliability review - {{.Lens.Name}} lens

{{.Lens.Focus}}

## Scope contract (strict)

- Analyze ONLY the change set below ({{.BaseDesc}}). Flag ONLY risks introduced or worsened by this change. Pre-existing issues in surrounding code are out of scope; do not report them.
- The full unified diff is inlined at the end of this prompt. It is the authoritative statement of what changed.
- The changed files exist as plain files under your working directory, a snapshot at {{.SnapshotDir}}. You MAY read the listed changed files there when the diff alone is not enough context. You MUST NOT explore, list, search, or read anything else: no other files, no directories, no repository history, no external resources.
{{- if .Deleted}}
- Deleted files are listed below for context only. They do not exist in the snapshot and must never be read.
{{- end}}
- Minimize turns: read the changed files at most once if you need to, then conclude. Do not iterate.

## Changed files
{{range .Present}}
- {{.Path}} ({{.Kind}}{{if .OldPath}}, renamed from {{.OldPath}}{{end}})
{{- end}}
{{- if .Deleted}}

## Deleted files (context only - these must never be read)
{{range .Deleted}}
- {{.}}
{{- end}}
{{- end}}

## Rule vocabulary (closed set)

Every finding's "rule" value MUST be exactly one of these slugs. A finding whose rule is not in this list will be dropped.
{{range .Lens.RuleVocab}}
- {{.}}
{{- end}}

## Output format

Output ONLY a single JSON object. No prose, no markdown fences, no commentary before or after it:

{"findings":[{"rule":"<one of the vocabulary slugs>","severity":"critical|high|medium|low","file":"<repo-relative path>","line":0,"title":"...","description":"...","recommendation":"..."}],"summary":"one sentence"}

- "rule": one of the vocabulary slugs above, exactly as written.
- "severity": one of critical, high, medium, low.
- "file" and "line": where the risk lives in the changed code; use line 0 when no single line applies.
- "title": short and specific. "description": why this change introduces or worsens the risk. "recommendation": the concrete fix.
- If this change introduces no risks visible to this lens, output {"findings":[],"summary":"<one sentence saying so>"}.

## Unified diff ({{.BaseDesc}})

{{.Diff}}

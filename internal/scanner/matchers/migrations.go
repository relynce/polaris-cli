package matchers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// migrationMatchers returns matchers that operate on SQL migration
// files. Each fires once per matching file rather than once per scan.
func migrationMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		rollbackMigrationMissingDown(),
		integerColumnNotBigint(),
	}
}

// rollbackMigrationMissingDown flags *.up.sql / *_up.sql migration
// files that have no corresponding *.down.sql / *_down.sql sibling.
//
// Corpus pattern: "Failed Rollback Leads to Outage" (19x in
// po-fayz.16 survey). The reliability concern: a migration without a
// committed rollback path forces operators to reverse-engineer the
// rollback under incident pressure, which is exactly when mistakes
// compound.
func rollbackMigrationMissingDown() scanner.Matcher {
	check := func(absPath, relPath string, _ []byte) []scanner.Candidate {
		base := filepath.Base(relPath)
		// Determine which naming convention this file uses.
		var sibling string
		switch {
		case strings.HasSuffix(base, ".up.sql"):
			sibling = strings.TrimSuffix(base, ".up.sql") + ".down.sql"
		case strings.HasSuffix(base, "_up.sql"):
			sibling = strings.TrimSuffix(base, "_up.sql") + "_down.sql"
		default:
			return nil // file pattern matched but neither convention
		}
		dir := filepath.Dir(absPath)
		if _, err := os.Stat(filepath.Join(dir, sibling)); err == nil {
			return nil
		}
		return []scanner.Candidate{{
			Slug:        "rollback-migration-missing-down",
			File:        relPath,
			LineNumber:  1,
			Snippet:     "no '" + sibling + "' alongside this migration",
			Description: "migration ships without a committed rollback; operators must reverse-engineer it under incident pressure",
		}}
	}

	return scanner.Matcher{
		Slug:         "rollback-migration-missing-down",
		Description:  "SQL migration without a corresponding *.down.sql rollback",
		Category:     "change_management",
		ControlCodes: []string{"RC-026"},
		FilePatterns: []string{
			"**/migrations/*.up.sql",
			"**/migrations/*_up.sql",
			"**/db/migrations/*.up.sql",
			"**/db/migrations/*_up.sql",
		},
		Confidence: "high",
		Severity:   "high",
		Impl:       scanner.ImplHeuristic,
		Source:     "curated",
		Check:      check,
		Provenance: scanner.Provenance{
			FailureDescription: "Migration ships without a tested rollback path; reversing under incident pressure compounds errors",
			IncidentFrequency:  "Pattern 'Failed Rollback Leads to Outage' observed 19x in the corpus survey (po-fayz.16)",
			TypicalBlastRadius: "multi-service when shared DB",
			TypicalMTTR:        "30-120 minutes",
			SourcePatternTypes: []string{"anti_pattern"},
			RelatedControls:    []string{"RC-026"},
		},
	}
}

// integerColumnNotBigint flags 32-bit integer columns whose names
// suggest unbounded growth — primary keys, foreign keys, counters.
// At ~2.1B max for INT4, these columns hit overflow in production-scale
// systems.
//
// Corpus pattern: "Integer Overflow in Database Column" — 55x in
// po-fayz.16 survey, the most common reliability pattern observed.
//
// Detection scope: column declarations in CREATE TABLE / ADD COLUMN /
// ALTER TABLE statements where the column name is a typical
// growth-unbounded name AND the type is INTEGER/INT/INT4 (32-bit). The
// check requires both: a column named `id` with type SMALLINT is also
// risky but covered by SMALLINT-specific matchers if added.
func integerColumnNotBigint() scanner.Matcher {
	// Names that suggest unbounded growth. Conservative list — broader
	// names like 'index' or 'value' would produce too many false
	// positives.
	growthNames := map[string]bool{
		"id":         true,
		"user_id":    true,
		"account_id": true,
		"order_id":   true,
		"event_id":   true,
		"session_id": true,
		"trace_id":   true,
		"request_id": true,
		"job_id":     true,
		"count":      true,
		"total":      true,
		"seq":        true,
		"sequence":   true,
		"version":    true,
	}
	growthSuffixes := []string{"_id", "_count", "_total", "_seq"}

	// createTableRE captures the table name of the most recent CREATE TABLE
	// statement so we can populate SQLTable on emitted Candidates.
	// Conservative: matches `CREATE TABLE [IF NOT EXISTS] [schema.]name`.
	createTableRE := regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?([a-zA-Z_][a-zA-Z0-9_]*)`)
	// alterAddColumnRE captures the table name from `ALTER TABLE x ADD COLUMN ...`.
	alterAddColumnRE := regexp.MustCompile(`(?i)^\s*ALTER\s+TABLE\s+(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?([a-zA-Z_][a-zA-Z0-9_]*)\s+ADD\s+COLUMN\b`)

	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		text := string(src)
		var out []scanner.Candidate
		seen := map[string]bool{}
		currentTable := ""

		for lineNum, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)

			// Track the enclosing table so per-column rollup works
			// correctly: 'id INTEGER' in two different tables must
			// produce two findings, not one.
			if m := createTableRE.FindStringSubmatch(line); m != nil {
				currentTable = strings.ToLower(m[1])
			} else if m := alterAddColumnRE.FindStringSubmatch(line); m != nil {
				currentTable = strings.ToLower(m[1])
			}

			// Skip non-DDL lines fast.
			if !strings.Contains(lower, " int") &&
				!strings.Contains(lower, "\tint") &&
				!strings.Contains(lower, " integer") &&
				!strings.Contains(lower, " serial") &&
				!strings.Contains(lower, "\tserial") {
				continue
			}
			// Skip comments.
			if strings.HasPrefix(line, "--") || strings.HasPrefix(line, "#") {
				continue
			}

			// Extract the column name (first identifier on the line for
			// column declarations; skip if the line is a constraint or
			// statement).
			fields := splitSQLFields(line)
			if len(fields) < 2 {
				continue
			}
			colName := strings.ToLower(strings.Trim(fields[0], `"`+"`,()"))
			colType := strings.ToLower(fields[1])
			// 32-bit int types only — BIGINT/INT8 are correctly sized,
			// SMALLINT is small but rarely overflows in this context.
			if !is32BitInteger(colType) {
				continue
			}
			if !isGrowthUnboundedName(colName, growthNames, growthSuffixes) {
				continue
			}
			key := relPath + ":" + colName
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, scanner.Candidate{
				Slug:        "integer-column-not-bigint",
				File:        relPath,
				LineNumber:  lineNum + 1,
				Snippet:     "column '" + colName + "' is " + colType + " — should be BIGINT",
				Description: "growth-unbounded column declared with 32-bit INTEGER (max ~2.1B); use BIGINT to avoid overflow",
				SQLTable:    currentTable,
				SQLColumn:   colName,
			})
		}
		return out
	}

	return scanner.Matcher{
		Slug:         "integer-column-not-bigint",
		Description:  "Growth-unbounded column declared as 32-bit INTEGER",
		Category:     "service_fragility",
		ControlCodes: []string{"RC-041"},
		FilePatterns: []string{
			"**/*.sql",
			"**/migrations/*",
			"**/db/migrations/*",
		},
		// W3: demo/seed/reset/cleanup scripts are dev-only fixtures; they
		// don't represent production schema decisions and produce
		// unactionable findings. Excluded by glob rather than directory
		// so legitimate scripts/ files (e.g., production data import
		// helpers) are still scanned.
		ExcludePatterns: []string{
			"**/scripts/*demo*.sql",
			"**/scripts/*seed*.sql",
			"**/scripts/reset_*.sql",
			"**/scripts/cleanup_*.sql",
			"**/scripts/create-stpa-*.sql",
		},
		Confidence: "high",
		Severity:   "high",
		Impl:       scanner.ImplHeuristic,
		Source:     "curated",
		Check:      check,
		Provenance: scanner.Provenance{
			FailureDescription: "32-bit integer column overflows at ~2.1B inserts; recovery requires emergency table rewrite under load",
			IncidentFrequency:  "55x in corpus survey — the most common reliability pattern observed (po-fayz.16)",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "1-3 hours",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-041"},
		},
		// Rollup per (table, column): a column declared in 000_initial
		// and later re-declared by another migration is one decision
		// point, not N. Falls back to per-location when SQLTable is
		// empty (loose `id INTEGER` outside a CREATE TABLE context).
		RollupKey: scanner.RollupByProject,
	}
}

// splitSQLFields splits a SQL DDL line on whitespace, treating
// parentheses and commas as structural separators.
func splitSQLFields(line string) []string {
	// Strip trailing comma; collapse runs of whitespace.
	line = strings.TrimRight(line, ",")
	var fields []string
	var current strings.Builder
	for _, r := range line {
		switch r {
		case ' ', '\t':
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

func is32BitInteger(t string) bool {
	t = strings.TrimRight(t, ",;()")
	switch t {
	case "int", "int4", "integer", "serial", "serial4":
		return true
	}
	return false
}

func isGrowthUnboundedName(name string, growthNames map[string]bool, growthSuffixes []string) bool {
	if growthNames[name] {
		return true
	}
	for _, s := range growthSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

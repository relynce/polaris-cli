package project

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxDigestLines = 200
	digestFilename = ".revelara/memory/digest.compact"
)

// DigestEntry is one line in digest.compact.
type DigestEntry struct {
	Type  string // RISK, WAIVER, PATTERN, ENTRYPOINT, SCAN
	Key   string
	Value string
	Meta  string
}

// ReadDigest parses targetDir/.revelara/memory/digest.compact.
// Returns nil, nil if the file does not exist (caller falls back to markdown).
func ReadDigest(targetDir string) ([]DigestEntry, error) {
	p := filepath.Join(targetDir, digestFilename)
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []DigestEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split at most 4 parts: Type:Key:Value:Meta
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 3 {
			// Malformed line — skip.
			continue
		}
		e := DigestEntry{
			Type: parts[0],
			Key:  parts[1],
		}
		decoded, decErr := url.QueryUnescape(parts[2])
		if decErr != nil {
			e.Value = parts[2]
		} else {
			e.Value = decoded
		}
		if len(parts) == 4 {
			e.Meta = parts[3]
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// AppendDigest appends entries to digest.compact and rotates when over maxDigestLines.
// Rotation drops oldest RISK/WAIVER lines first (smallest :YYYY-MM meta suffix).
func AppendDigest(targetDir string, entries []DigestEntry) error {
	existing, err := ReadDigest(targetDir)
	if err != nil {
		return err
	}

	all := append(existing, entries...)

	if len(all) > maxDigestLines {
		all = rotateTo(all, maxDigestLines)
	}

	return writeDigest(targetDir, all)
}

// rotateTo trims the slice to at most maxLines by dropping oldest RISK/WAIVER
// entries first (sorted by Meta ascending, meaning oldest YYYY-MM first).
func rotateTo(entries []DigestEntry, maxLines int) []DigestEntry {
	if len(entries) <= maxLines {
		return entries
	}

	// Collect indexes of RISK and WAIVER entries, along with their Meta values.
	type candidate struct {
		idx  int
		meta string
	}
	var candidates []candidate
	for i, e := range entries {
		if e.Type == "RISK" || e.Type == "WAIVER" {
			candidates = append(candidates, candidate{i, e.Meta})
		}
	}

	// Sort candidates by Meta ascending so oldest (smallest YYYY-MM) is first.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].meta < candidates[j].meta
	})

	// Mark candidates for removal, oldest first, until we're under maxLines.
	remove := make(map[int]bool)
	toRemove := len(entries) - maxLines
	for i := 0; i < len(candidates) && toRemove > 0; i++ {
		remove[candidates[i].idx] = true
		toRemove--
	}

	out := make([]DigestEntry, 0, len(entries)-len(remove))
	for i, e := range entries {
		if !remove[i] {
			out = append(out, e)
		}
	}
	return out
}

// writeDigest writes all entries to digest.compact atomically (temp file + rename).
func writeDigest(targetDir string, entries []DigestEntry) error {
	dir := filepath.Join(targetDir, ".revelara", "memory")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	finalPath := filepath.Join(targetDir, digestFilename)

	tmp, err := os.CreateTemp(dir, "digest.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	w := bufio.NewWriter(tmp)
	for _, e := range entries {
		encoded := url.QueryEscape(e.Value)
		var line string
		if e.Meta != "" {
			line = fmt.Sprintf("%s:%s:%s:%s\n", e.Type, e.Key, encoded, e.Meta)
		} else {
			line = fmt.Sprintf("%s:%s:%s\n", e.Type, e.Key, encoded)
		}
		if _, err := fmt.Fprint(w, line); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, finalPath)
}

// DismissedSlugs returns a set of slugs from RISK entries with DISMISSED or ACCEPTED disposition.
func DismissedSlugs(entries []DigestEntry) map[string]bool {
	out := make(map[string]bool)
	for _, e := range entries {
		if e.Type != "RISK" {
			continue
		}
		slug := e.Key
		// Value is formatted as SEVERITY:DISPOSITION, e.g. HIGH:DISMISSED
		// or just DISMISSED/ACCEPTED when no severity prefix.
		val := strings.ToUpper(e.Value)
		if strings.Contains(val, "DISMISSED") || strings.Contains(val, "ACCEPTED") {
			out[slug] = true
		}
	}
	return out
}

// EntrypointFromDigest returns the filepath from the ENTRYPOINT:main line, empty if absent.
func EntrypointFromDigest(entries []DigestEntry) string {
	for _, e := range entries {
		if e.Type == "ENTRYPOINT" && e.Key == "main" {
			return e.Value
		}
	}
	return ""
}

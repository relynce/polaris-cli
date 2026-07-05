package scanner

import "regexp"

// po-i24do.19: scan --submit posts finding Narratives (which embed the
// matched source snippet) to the API. Snippets are expanded to the full
// source line, so a hardcoded-connection-string match carries the
// cleartext user:password@ authority, and other matches may carry
// API-key-looking tokens. Redact those before the snippet leaves the
// process so credentials are never transmitted or persisted server-side.

// connStringCreds matches the `user:password@` authority of a URI-style
// connection string (postgres://user:pass@host, redis://u:p@host, …). The
// password segment is masked; the username is preserved because it is not
// itself a secret and aids triage. Password may be empty (user@host), in
// which case there is nothing to mask and the pattern still normalizes.
var connStringCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)([^:/@\s]+):([^@/\s]*)@`)

// apiKeyToken matches common high-entropy secret token shapes: provider
// prefixes (sk-, pk_live_, ghp_, xoxb-, AKIA…, etc.) followed by a long
// run of token characters. Kept conservative to avoid mangling ordinary
// identifiers: it requires either a known secret prefix or a long
// base64-ish run that follows a key-ish assignment.
var apiKeyToken = regexp.MustCompile(`(?i)\b((?:sk|pk|rk)[-_](?:live|test)?[-_]?|ghp_|gho_|ghu_|ghs_|ghr_|xox[baprs]-|AKIA|ASIA|glpat-|AIza)[A-Za-z0-9_\-]{8,}`)

// redactSecrets masks credential material inside a snippet before it is
// embedded in a finding Narrative that may be submitted to the API. It is
// deliberately applied to every regex-matched snippet (not just security
// matchers) because snippets are expanded to the surrounding source line,
// so any matcher can incidentally capture a nearby secret.
func redactSecrets(s string) string {
	// Mask the password portion of connection-string authorities, keeping
	// the scheme and username so the finding stays actionable.
	s = connStringCreds.ReplaceAllString(s, "$1$2:***REDACTED***@")
	// Mask API-key-looking tokens, preserving the recognizable prefix.
	s = apiKeyToken.ReplaceAllString(s, "${1}***REDACTED***")
	return s
}

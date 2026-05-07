package matchers

import (
	"regexp"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// iacMatchers returns matchers for Kubernetes YAML, Dockerfile, and
// Terraform files. They run on file globs rather than language
// detection (the engine selects them when matching files exist).
func iacMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		k8sNoReadinessProbe(),
		k8sNoLivenessProbe(),
		k8sMissingResourceLimits(),
		dockerfileNoHealthcheck(),
		terraformNoEncryption(),
	}
}

// splitYAMLDocs splits a multi-document YAML stream on `---`
// separators. Returns (doc, startLine) pairs where startLine is the
// 1-based line of the first non-separator line in the document. Used by
// the K8s matchers to scope checks per-resource.
func splitYAMLDocs(src []byte) []yamlDoc {
	type acc struct {
		buf       strings.Builder
		startLine int
	}
	var (
		out  []yamlDoc
		curr acc
	)
	curr.startLine = 1
	line := 0
	flush := func() {
		s := curr.buf.String()
		if strings.TrimSpace(s) != "" {
			out = append(out, yamlDoc{Body: s, StartLine: curr.startLine})
		}
		curr = acc{}
	}
	scanner := strings.Split(string(src), "\n")
	for i, l := range scanner {
		line = i + 1
		if strings.TrimSpace(l) == "---" {
			flush()
			curr.startLine = line + 1
			continue
		}
		curr.buf.WriteString(l)
		curr.buf.WriteByte('\n')
	}
	flush()
	return out
}

type yamlDoc struct {
	Body      string
	StartLine int
}

// findK8sKind reports whether doc declares the given Kubernetes kind
// at top level, plus the line offset (1-based, within doc) of the kind line.
func findK8sKind(doc string, kind string) (bool, int) {
	re := regexp.MustCompile(`(?m)^kind:\s*` + regexp.QuoteMeta(kind) + `\s*$`)
	loc := re.FindStringIndex(doc)
	if loc == nil {
		return false, 0
	}
	return true, lineOf(doc, loc[0])
}

func lineOf(s string, off int) int {
	if off > len(s) {
		off = len(s)
	}
	return strings.Count(s[:off], "\n") + 1
}

// k8sNoReadinessProbe flags Deployments/StatefulSets/DaemonSets without
// a readinessProbe declared anywhere in the document.
func k8sNoReadinessProbe() scanner.Matcher {
	return k8sMissingFieldMatcher(missingFieldSpec{
		Slug:        "no-readiness-probe",
		Description: "Kubernetes workload without readinessProbe",
		Field:       "readinessProbe",
		ControlCode: "RC-024",
		Severity:    "high",
		Confidence:  "high",
		Provenance: scanner.Provenance{
			FailureDescription: "Traffic hits pods before they are ready, producing 502/503 spikes during deploys",
			IncidentFrequency:  "Top Kubernetes deployment incident pattern",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "rollback latency",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-024"},
		},
	})
}

func k8sNoLivenessProbe() scanner.Matcher {
	return k8sMissingFieldMatcher(missingFieldSpec{
		Slug:        "no-liveness-probe",
		Description: "Kubernetes workload without livenessProbe",
		Field:       "livenessProbe",
		ControlCode: "RC-024",
		Severity:    "medium",
		Confidence:  "medium",
		Provenance: scanner.Provenance{
			FailureDescription: "Stuck processes are not detected and restarted",
			IncidentFrequency:  "Observed in 'hung process' incident patterns",
			TypicalBlastRadius: "pod-level",
			TypicalMTTR:        "elevated until manual intervention",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-024"},
		},
	})
}

func k8sMissingResourceLimits() scanner.Matcher {
	return k8sMissingFieldMatcher(missingFieldSpec{
		Slug:        "missing-resource-limits",
		Description: "Kubernetes container without resource limits",
		Field:       "limits:",
		ControlCode: "RC-025",
		Severity:    "high",
		Confidence:  "high",
		Provenance: scanner.Provenance{
			FailureDescription: "Unbounded resource usage causes noisy-neighbor failures and node-level OOM",
			IncidentFrequency:  "Common in multi-tenant cluster incidents",
			TypicalBlastRadius: "node-level",
			TypicalMTTR:        "30-60 minutes",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-025"},
		},
	})
}

type missingFieldSpec struct {
	Slug        string
	Description string
	Field       string // searched literally in the workload doc
	ControlCode string
	Severity    string
	Confidence  string
	Provenance  scanner.Provenance
}

// k8sMissingFieldMatcher builds a heuristic matcher that scans
// Deployment/StatefulSet/DaemonSet documents for an absent field.
func k8sMissingFieldMatcher(spec missingFieldSpec) scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		var out []scanner.Candidate
		fieldRe := regexp.MustCompile(regexp.QuoteMeta(spec.Field))
		for _, doc := range splitYAMLDocs(src) {
			ok, kindLine := false, 0
			for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
				if has, line := findK8sKind(doc.Body, kind); has {
					ok = true
					kindLine = line
					break
				}
			}
			if !ok {
				continue
			}
			if fieldRe.FindString(doc.Body) != "" {
				continue
			}
			out = append(out, scanner.Candidate{
				Slug:        spec.Slug,
				File:        relPath,
				LineNumber:  doc.StartLine + kindLine - 1,
				Snippet:     "K8s workload missing " + spec.Field,
				Description: spec.Description,
			})
		}
		return out
	}

	return scanner.Matcher{
		Slug:         spec.Slug,
		Description:  spec.Description,
		Category:     "change_management",
		ControlCodes: []string{spec.ControlCode},
		FilePatterns: []string{"**/*.yaml", "**/*.yml"},
		Confidence:   spec.Confidence,
		Severity:     spec.Severity,
		Impl:         scanner.ImplHeuristic,
		Source:       "curated",
		Check:        check,
		Provenance:   spec.Provenance,
	}
}

// dockerfileNoHealthcheck flags Dockerfiles without a HEALTHCHECK
// instruction.
func dockerfileNoHealthcheck() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		text := string(src)
		// Quick check: is this a Dockerfile? File-pattern matching
		// already filters, so the engine only invokes this for
		// Dockerfile-named files. But guard against edge cases.
		if !regexp.MustCompile(`(?m)^\s*FROM\s+\S`).MatchString(text) {
			return nil
		}
		if regexp.MustCompile(`(?m)^\s*HEALTHCHECK\b`).MatchString(text) {
			return nil
		}
		return []scanner.Candidate{{
			Slug:        "dockerfile-no-healthcheck",
			File:        relPath,
			LineNumber:  1,
			Snippet:     "Dockerfile missing HEALTHCHECK instruction",
			Description: "Dockerfile has no HEALTHCHECK; orchestrator can't detect unhealthy containers",
		}}
	}

	return scanner.Matcher{
		Slug:         "dockerfile-no-healthcheck",
		Description:  "Dockerfile without HEALTHCHECK instruction",
		Category:     "change_management",
		ControlCodes: []string{"RC-024"},
		FilePatterns: []string{"Dockerfile", "Dockerfile.*", "**/Dockerfile", "**/Dockerfile.*"},
		Confidence:   "medium",
		Severity:     "medium",
		Impl:         scanner.ImplHeuristic,
		Source:       "curated",
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Without HEALTHCHECK the orchestrator routes traffic to dead containers",
			IncidentFrequency:  "Contributes to 'traffic sent to dead container' incidents",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "varies",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-024"},
		},
	}
}

// terraformNoEncryption flags AWS S3 buckets, RDS instances, and EBS
// volumes that don't configure encryption.
func terraformNoEncryption() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		text := string(src)
		var out []scanner.Candidate

		// S3 bucket without server-side encryption configuration.
		// Note: the modern recommendation is a separate
		// aws_s3_bucket_server_side_encryption_configuration resource;
		// we accept either inline server_side_encryption_configuration
		// or a sibling resource on the same file.
		s3Re := regexp.MustCompile(`(?m)^resource\s+"aws_s3_bucket"\s+`)
		s3SSEPresent := strings.Contains(text, "aws_s3_bucket_server_side_encryption_configuration") ||
			strings.Contains(text, "server_side_encryption_configuration")
		if s3Re.FindStringIndex(text) != nil && !s3SSEPresent {
			loc := s3Re.FindStringIndex(text)
			out = append(out, scanner.Candidate{
				Slug:        "terraform-no-encryption",
				File:        relPath,
				LineNumber:  lineOf(text, loc[0]),
				Snippet:     "aws_s3_bucket without server-side encryption configuration",
				Description: "S3 bucket lacks server-side encryption",
			})
		}

		// RDS without storage_encrypted = true.
		rdsRe := regexp.MustCompile(`(?m)^resource\s+"aws_db_instance"\s+`)
		if loc := rdsRe.FindStringIndex(text); loc != nil {
			if !regexp.MustCompile(`storage_encrypted\s*=\s*true`).MatchString(text) {
				out = append(out, scanner.Candidate{
					Slug:        "terraform-no-encryption",
					File:        relPath,
					LineNumber:  lineOf(text, loc[0]),
					Snippet:     "aws_db_instance without storage_encrypted = true",
					Description: "RDS instance not encrypted at rest",
				})
			}
		}

		// EBS without encrypted = true.
		ebsRe := regexp.MustCompile(`(?m)^resource\s+"aws_ebs_volume"\s+`)
		if loc := ebsRe.FindStringIndex(text); loc != nil {
			if !regexp.MustCompile(`(?m)^\s*encrypted\s*=\s*true`).MatchString(text) {
				out = append(out, scanner.Candidate{
					Slug:        "terraform-no-encryption",
					File:        relPath,
					LineNumber:  lineOf(text, loc[0]),
					Snippet:     "aws_ebs_volume without encrypted = true",
					Description: "EBS volume not encrypted",
				})
			}
		}
		return out
	}

	return scanner.Matcher{
		Slug:         "terraform-no-encryption",
		Description:  "Terraform AWS resource without encryption configuration",
		Category:     "disaster_recovery",
		ControlCodes: []string{"RC-031"},
		FilePatterns: []string{"**/*.tf"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         scanner.ImplHeuristic,
		Source:       "curated",
		Floor:        true, // po-qs96.2: unencrypted PII at rest is compliance/security, not a reliability tradeoff
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Unencrypted storage is a compliance failure and a data-loss risk on disk theft",
			IncidentFrequency:  "Present in 'data exposure' incidents",
			TypicalBlastRadius: "data-level",
			TypicalMTTR:        "extended; recovery requires re-provisioning",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-031"},
		},
	}
}

package matchers

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// Pod-spec carrying workload kinds. Pod spec location varies:
//   - Pod: spec.containers
//   - Deployment, StatefulSet, DaemonSet, ReplicaSet, Job: spec.template.spec.containers
//   - CronJob: spec.jobTemplate.spec.template.spec.containers
var podSpecPathByKind = map[string][]string{
	"Pod":         {"spec"},
	"Deployment":  {"spec", "template", "spec"},
	"StatefulSet": {"spec", "template", "spec"},
	"DaemonSet":   {"spec", "template", "spec"},
	"ReplicaSet":  {"spec", "template", "spec"},
	"Job":         {"spec", "template", "spec"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template", "spec"},
}

// podContainer is the per-container view walkPodContainers hands to the
// caller. Resources may be nil if the container has no resources block.
type podContainer struct {
	Kind         string
	Name         string     // container name
	WorkloadName string     // metadata.name of the enclosing workload (Deployment, StatefulSet, etc.)
	Line         int        // 1-based file line of the container's '- name:' entry
	Resources    *yaml.Node // mapping node for resources, or nil
}

// walkPodContainers parses a (possibly multi-doc) YAML stream and invokes
// fn for every container and initContainer in every supported workload
// kind. Errors during parsing are silently ignored so a single malformed
// document doesn't suppress findings on the rest of the file.
func walkPodContainers(src []byte, fn func(c podContainer)) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			return
		}
		if err != nil {
			return
		}
		root := docRoot(&doc)
		if root == nil {
			continue
		}
		kind := mapStringValue(root, "kind")
		path, ok := podSpecPathByKind[kind]
		if !ok {
			continue
		}
		workloadName := mapStringValue(mapValue(root, "metadata"), "name")
		podSpec := descend(root, path)
		if podSpec == nil {
			continue
		}
		for _, listKey := range []string{"containers", "initContainers"} {
			list := mapValue(podSpec, listKey)
			if list == nil || list.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range list.Content {
				if item.Kind != yaml.MappingNode {
					continue
				}
				name := mapStringValue(item, "name")
				fn(podContainer{
					Kind:         kind,
					Name:         name,
					WorkloadName: workloadName,
					Line:         item.Line,
					Resources:    mapValue(item, "resources"),
				})
			}
		}
	}
}

// docRoot returns the root mapping node of a yaml.Document or the node
// itself if it's already a mapping.
func docRoot(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

// mapValue returns the value node for key in a MappingNode, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content)-1; i += 2 {
		k := m.Content[i]
		if k.Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapStringValue returns the scalar string value of m[key], or "".
func mapStringValue(m *yaml.Node, key string) string {
	v := mapValue(m, key)
	if v == nil || v.Kind != yaml.ScalarNode {
		return ""
	}
	return v.Value
}

// descend follows a key path through nested MappingNodes.
func descend(root *yaml.Node, path []string) *yaml.Node {
	n := root
	for _, key := range path {
		n = mapValue(n, key)
		if n == nil {
			return nil
		}
	}
	return n
}

// hasLimit reports whether resources.limits.<resource> is set to a
// non-empty scalar value.
func hasLimit(resources *yaml.Node, resource string) bool {
	if resources == nil {
		return false
	}
	limits := mapValue(resources, "limits")
	if limits == nil {
		return false
	}
	return mapStringValue(limits, resource) != ""
}

// limitBelowRequest reports (true, limitVal, requestVal) if both
// resources.requests.<resource> and resources.limits.<resource> are set
// and limit < request.
func limitBelowRequest(resources *yaml.Node, resource string) (bool, string, string) {
	if resources == nil {
		return false, "", ""
	}
	limits := mapValue(resources, "limits")
	requests := mapValue(resources, "requests")
	if limits == nil || requests == nil {
		return false, "", ""
	}
	lStr := mapStringValue(limits, resource)
	rStr := mapStringValue(requests, resource)
	if lStr == "" || rStr == "" {
		return false, "", ""
	}
	lv, err := parseQuantity(lStr)
	if err != nil {
		return false, "", ""
	}
	rv, err := parseQuantity(rStr)
	if err != nil {
		return false, "", ""
	}
	if lv < rv {
		return true, lStr, rStr
	}
	return false, "", ""
}

// parseQuantity parses a subset of the Kubernetes quantity format.
// Supports binary suffixes (Ki, Mi, Gi, Ti, Pi, Ei), decimal suffixes
// (K, M, G, T, P, E), and the SI sub-unit suffixes m, u, n.
func parseQuantity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty quantity")
	}
	// Order matters: longest suffix first so "Mi" wins over "M".
	type suf struct {
		s string
		m float64
	}
	suffixes := []suf{
		{"Ei", 1 << 60}, {"Pi", 1 << 50}, {"Ti", 1 << 40},
		{"Gi", 1 << 30}, {"Mi", 1 << 20}, {"Ki", 1 << 10},
		{"E", 1e18}, {"P", 1e15}, {"T", 1e12},
		{"G", 1e9}, {"M", 1e6}, {"K", 1e3}, {"k", 1e3},
		{"m", 1e-3}, {"u", 1e-6}, {"n", 1e-9},
	}
	for _, x := range suffixes {
		if num, ok := strings.CutSuffix(s, x.s); ok {
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, err
			}
			return f * x.m, nil
		}
	}
	return strconv.ParseFloat(s, 64)
}

// k8sMissingMemoryLimit flags containers without resources.limits.memory.
func k8sMissingMemoryLimit() scanner.Matcher {
	return resourceLimitMatcher(resourceLimitSpec{
		Slug:        "k8s-missing-memory-limit",
		Description: "Kubernetes container without memory limit",
		Resource:    "memory",
		Mode:        modeMissing,
	})
}

// k8sMissingCPULimit flags containers without resources.limits.cpu.
func k8sMissingCPULimit() scanner.Matcher {
	return resourceLimitMatcher(resourceLimitSpec{
		Slug:        "k8s-missing-cpu-limit",
		Description: "Kubernetes container without CPU limit",
		Resource:    "cpu",
		Mode:        modeMissing,
	})
}

// k8sLimitBelowRequest flags containers where any resource limit is
// strictly less than its corresponding request.
func k8sLimitBelowRequest() scanner.Matcher {
	return resourceLimitMatcher(resourceLimitSpec{
		Slug:        "k8s-limit-below-request",
		Description: "Kubernetes container with resource limit below request",
		Mode:        modeBelowRequest,
	})
}

type limitMode int

const (
	modeMissing limitMode = iota
	modeBelowRequest
)

type resourceLimitSpec struct {
	Slug        string
	Description string
	Resource    string // "memory" or "cpu" for modeMissing; ignored for modeBelowRequest
	Mode        limitMode
}

// resourceLimitMatcher builds a matcher whose Check walks pod containers
// and emits one Candidate per offending container.
func resourceLimitMatcher(spec resourceLimitSpec) scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		var out []scanner.Candidate
		walkPodContainers(src, func(c podContainer) {
			switch spec.Mode {
			case modeMissing:
				if hasLimit(c.Resources, spec.Resource) {
					return
				}
				out = append(out, scanner.Candidate{
					Slug:        spec.Slug,
					File:        relPath,
					LineNumber:  c.Line,
					Snippet:     fmt.Sprintf("container %q missing %s limit", c.Name, spec.Resource),
					Description: spec.Description,
					K8sKind:     c.Kind,
					K8sName:     c.WorkloadName,
				})
			case modeBelowRequest:
				for _, resource := range []string{"memory", "cpu"} {
					below, lv, rv := limitBelowRequest(c.Resources, resource)
					if !below {
						continue
					}
					out = append(out, scanner.Candidate{
						Slug:        spec.Slug,
						File:        relPath,
						LineNumber:  c.Line,
						Snippet:     fmt.Sprintf("container %q %s limit %s < request %s", c.Name, resource, lv, rv),
						Description: spec.Description,
						K8sKind:     c.Kind,
						K8sName:     c.WorkloadName,
					})
				}
			}
		})
		return out
	}

	return scanner.Matcher{
		Slug:         spec.Slug,
		Description:  spec.Description,
		Category:     "change_management",
		ControlCodes: []string{"RC-025"},
		FilePatterns: []string{"**/*.yaml", "**/*.yml"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         scanner.ImplHeuristic,
		Source:       "curated",
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Unbounded or misconfigured resource usage causes noisy-neighbor failures and node-level OOM",
			IncidentFrequency:  "Common in multi-tenant cluster incidents",
			TypicalBlastRadius: "node-level",
			TypicalMTTR:        "30-60 minutes",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-025"},
		},
		// Rollup per (Kind, Name): the same Deployment patched across
		// dev/staging/prod overlays is one decision, not N. Container-
		// level granularity is preserved in Evidence.
		RollupKey: scanner.RollupByK8sWorkload,
	}
}

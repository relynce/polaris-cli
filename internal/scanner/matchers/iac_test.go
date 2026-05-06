package matchers

import "testing"

func runIaCMatcher(t *testing.T, m func() interface {}, src, file string) bool {
	t.Helper()
	_ = m
	return false
}

func TestK8sNoReadinessProbe(t *testing.T) {
	m := k8sNoReadinessProbe()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: deployment without readinessProbe",
			`apiVersion: apps/v1
kind: Deployment
metadata:
  name: x
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
`,
			true},
		{"good: deployment with readinessProbe",
			`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
          readinessProbe:
            httpGet:
              path: /healthz
`,
			false},
		{"skip: not a Deployment kind",
			`apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
`,
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cands := m.Check("/abs/d.yaml", "d.yaml", []byte(c.src))
			if (len(cands) > 0) != c.want {
				t.Errorf("fired=%v, want %v", len(cands) > 0, c.want)
			}
		})
	}
}

func TestK8sMissingResourceLimits(t *testing.T) {
	m := k8sMissingResourceLimits()
	bad := `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
`
	good := `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
          resources:
            limits:
              cpu: 200m
`
	if cands := m.Check("/abs/d.yaml", "d.yaml", []byte(bad)); len(cands) == 0 {
		t.Error("expected match on missing limits")
	}
	if cands := m.Check("/abs/d.yaml", "d.yaml", []byte(good)); len(cands) != 0 {
		t.Errorf("unexpected match when limits present: %+v", cands)
	}
}

func TestDockerfileNoHealthcheck(t *testing.T) {
	m := dockerfileNoHealthcheck()
	bad := "FROM alpine\nCMD [\"app\"]\n"
	good := "FROM alpine\nHEALTHCHECK CMD wget -q http://localhost/healthz\nCMD [\"app\"]\n"
	if cands := m.Check("/abs/Dockerfile", "Dockerfile", []byte(bad)); len(cands) == 0 {
		t.Error("expected match on missing HEALTHCHECK")
	}
	if cands := m.Check("/abs/Dockerfile", "Dockerfile", []byte(good)); len(cands) != 0 {
		t.Errorf("unexpected match when HEALTHCHECK present: %+v", cands)
	}
}

func TestTerraformNoEncryption(t *testing.T) {
	m := terraformNoEncryption()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: s3 without encryption",
			`resource "aws_s3_bucket" "x" {
  bucket = "name"
}
`,
			true},
		{"good: s3 with separate sse resource",
			`resource "aws_s3_bucket" "x" {
  bucket = "name"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "x" {
  bucket = aws_s3_bucket.x.id
}
`,
			false},
		{"bad: rds without storage_encrypted",
			`resource "aws_db_instance" "x" {
  allocated_storage = 10
}
`,
			true},
		{"good: rds with storage_encrypted",
			`resource "aws_db_instance" "x" {
  allocated_storage = 10
  storage_encrypted = true
}
`,
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cands := m.Check("/abs/main.tf", "main.tf", []byte(c.src))
			if (len(cands) > 0) != c.want {
				t.Errorf("fired=%v, want %v", len(cands) > 0, c.want)
			}
		})
	}
}

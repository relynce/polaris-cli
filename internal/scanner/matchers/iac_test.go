package matchers

import "testing"

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

func TestK8sMissingMemoryLimit(t *testing.T) {
	m := k8sMissingMemoryLimit()
	cases := []struct {
		name string
		src  string
		want int // expected candidate count
	}{
		{"bad: no resources block at all",
			`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
`, 1},
		{"bad: cpu-only limits, no memory",
			`apiVersion: apps/v1
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
`, 1},
		{"good: memory limit present",
			`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
          resources:
            limits:
              memory: 256Mi
`, 0},
		{"partial: one of two containers missing memory limit",
			`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: ok
          image: alpine
          resources:
            limits:
              memory: 256Mi
              cpu: 200m
        - name: bad
          image: alpine
`, 1},
		{"pod: Pod kind covered",
			`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: c
      image: alpine
`, 1},
		{"cronjob: CronJob deep nesting covered",
			`apiVersion: batch/v1
kind: CronJob
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: c
              image: alpine
`, 1},
		{"job: Job kind covered",
			`apiVersion: batch/v1
kind: Job
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
`, 1},
		{"replicaset: ReplicaSet kind covered",
			`apiVersion: apps/v1
kind: ReplicaSet
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
`, 1},
		{"initContainers also scanned",
			`apiVersion: v1
kind: Pod
spec:
  initContainers:
    - name: init
      image: alpine
  containers:
    - name: main
      image: alpine
      resources:
        limits:
          memory: 256Mi
          cpu: 200m
`, 1},
		{"skip: ConfigMap kind",
			`apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.Check("/abs/d.yaml", "d.yaml", []byte(c.src))
			if len(got) != c.want {
				t.Errorf("got %d candidates, want %d: %+v", len(got), c.want, got)
			}
		})
	}
}

func TestK8sMissingCPULimit(t *testing.T) {
	m := k8sMissingCPULimit()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"bad: memory-only limits, no cpu",
			`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: alpine
          resources:
            limits:
              memory: 256Mi
`, 1},
		{"good: cpu limit present",
			`apiVersion: apps/v1
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
              memory: 256Mi
`, 0},
		{"bad: no resources block",
			`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: c
      image: alpine
`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.Check("/abs/d.yaml", "d.yaml", []byte(c.src))
			if len(got) != c.want {
				t.Errorf("got %d, want %d: %+v", len(got), c.want, got)
			}
		})
	}
}

func TestK8sLimitBelowRequest(t *testing.T) {
	m := k8sLimitBelowRequest()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"bad: memory limit < memory request",
			`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: c
      image: alpine
      resources:
        requests:
          memory: 512Mi
        limits:
          memory: 256Mi
`, 1},
		{"bad: cpu limit < cpu request",
			`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: c
      image: alpine
      resources:
        requests:
          cpu: 500m
        limits:
          cpu: 200m
`, 1},
		{"good: limit >= request",
			`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: c
      image: alpine
      resources:
        requests:
          memory: 128Mi
          cpu: 100m
        limits:
          memory: 256Mi
          cpu: 200m
`, 0},
		{"good: requests only, no limits (different matcher's job)",
			`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: c
      image: alpine
      resources:
        requests:
          memory: 128Mi
`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.Check("/abs/d.yaml", "d.yaml", []byte(c.src))
			if len(got) != c.want {
				t.Errorf("got %d, want %d: %+v", len(got), c.want, got)
			}
		})
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

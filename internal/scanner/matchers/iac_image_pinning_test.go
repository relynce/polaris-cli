package matchers

import "testing"

func TestIsMutableImageReference(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		// No tag → implicit :latest → mutable
		{"redis", true},
		{"foo", true},
		{"gcr.io/distroless/static", true},
		{"us-docker.pkg.dev/proj/repo/image", true},
		{"localhost:5000/foo", true},

		// Explicit :latest
		{"redis:latest", true},
		{"gcr.io/distroless/static:latest", true},

		// Mutable distro-only tags
		{"redis:alpine", true},
		{"debian:slim", true},
		{"ubuntu:jammy", false}, // codename pin: out of curated mutable set
		{"alpine:edge", true},
		{"node:nightly", true},
		{"image:main", true},
		{"image:dev", true},
		{"image:stable", true},

		// Pinned tags
		{"redis:7.4.2-alpine", false},
		{"foo:v1.2.3", false},
		{"foo:1.2.3", false},
		{"foo:sha-abc1234", false},
		{"foo:2025-04-01", false},

		// Digest pins (immutable regardless of tag)
		{"foo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"foo:latest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"busybox:latest@sha256:b3255e7dfbcd10cb367af0d409747d511aeb66dfac98cf30e97e87e4207dd76f", false},

		// Registry with port
		{"localhost:5000/foo:v1", false},
		{"localhost:5000/foo:latest", true},
	}
	for _, c := range cases {
		t.Run(c.ref, func(t *testing.T) {
			if got := isMutableImageReference(c.ref); got != c.want {
				t.Errorf("isMutableImageReference(%q) = %v, want %v", c.ref, got, c.want)
			}
		})
	}
}

func TestK8sMutableImageTag(t *testing.T) {
	m := k8sMutableImageTag()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			"no tag, fires",
			`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: c
          image: paymentservice
`, 1,
		},
		{
			"latest, fires",
			`spec:
  containers:
    - image: redis:latest
`, 1,
		},
		{
			"alpine distro-tag, fires",
			`spec:
  containers:
    - image: redis:alpine
`, 1,
		},
		{
			"version-pinned, no fire",
			`spec:
  containers:
    - image: redis:7.4.2-alpine
`, 0,
		},
		{
			"digest-pinned, no fire (even with :latest)",
			`spec:
  containers:
    - image: busybox:latest@sha256:b3255e7dfbcd10cb367af0d409747d511aeb66dfac98cf30e97e87e4207dd76f
`, 0,
		},
		{
			"Helm template, skip",
			`spec:
  containers:
    - image: {{ .Values.images.repository }}/{{ .Values.adService.name }}:{{ .Values.images.tag | default .Chart.AppVersion }}
`, 0,
		},
		{
			"partial Helm template, skip",
			`spec:
  containers:
    - image: foo-{{ .Values.tag }}
`, 0,
		},
		{
			"multiple containers, fires per-bad",
			`spec:
  containers:
    - image: app:v1.0.0
    - image: sidecar:latest
    - image: helper
    - image: pinned:v2.0.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
`, 2,
		},
		{
			"initContainers also scanned",
			`spec:
  initContainers:
    - image: busybox:latest
  containers:
    - image: app:v1.0.0
`, 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.Check("/abs/test.yaml", "test.yaml", []byte(c.src))
			if len(got) != c.want {
				t.Errorf("got %d findings, want %d: %+v", len(got), c.want, got)
			}
		})
	}
}

func TestDockerfileMutableBaseImage(t *testing.T) {
	m := dockerfileMutableBaseImage()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"no tag, fires", "FROM gcr.io/distroless/static\n", 1},
		{"latest, fires", "FROM ubuntu:latest\n", 1},
		{"alpine, fires", "FROM redis:alpine\n", 1},
		{"version-pinned, no fire", "FROM ubuntu:24.04\n", 0},
		{"digest-pinned, no fire", "FROM ubuntu@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", 0},
		{"scratch, no fire", "FROM scratch\n", 0},
		{"build-arg substitution, skip", "ARG BASE\nFROM $BASE\n", 0},
		{"build-arg with braces, skip", "ARG BASE\nFROM ${BASE}:latest\n", 0},
		{
			"multi-stage with AS",
			`FROM golang:1.22-alpine AS builder
WORKDIR /src
FROM gcr.io/distroless/static
COPY --from=builder /app /app
`, 1, // golang:1.22-alpine is pinned by major.minor; distroless/static is mutable
		},
		{
			"case-insensitive FROM",
			"from ubuntu:latest\n", 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.Check("/abs/Dockerfile", "Dockerfile", []byte(c.src))
			if len(got) != c.want {
				t.Errorf("got %d findings, want %d: %+v", len(got), c.want, got)
			}
		})
	}
}

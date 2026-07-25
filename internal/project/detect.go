package project

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// DetectComponents scans a project root for deployable components.
// Uses a multi-phase approach: workspace declarations, build file scanning,
// language-specific patterns, and Dockerfile detection.
func DetectComponents(rootDir string) []ProjectComponent {
	var components []ProjectComponent
	seen := make(map[string]bool)

	addComponent := func(name, path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		components = append(components, ProjectComponent{Name: name, Path: path})
	}

	excludeDirs := map[string]bool{
		"node_modules": true, "vendor": true, "venv": true, ".venv": true,
		"target": true, "build": true, "dist": true, ".git": true,
		"__pycache__": true, ".tox": true, "env": true,
	}

	// Phase 1: Workspace declarations

	// Go workspaces (go.work)
	if data, err := os.ReadFile(filepath.Join(rootDir, "go.work")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "use ") || (strings.HasPrefix(line, "./") && !strings.HasPrefix(line, "//")) {
				dir := strings.TrimPrefix(line, "use ")
				dir = strings.TrimSpace(dir)
				dir = strings.Trim(dir, "./")
				if dir != "" && dir != "." {
					name := filepath.Base(dir)
					addComponent(name, dir+"/")
				}
			}
		}
	}

	// Rust workspaces (Cargo.toml [workspace] members)
	if data, err := os.ReadFile(filepath.Join(rootDir, "Cargo.toml")); err == nil {
		content := string(data)
		if strings.Contains(content, "[workspace]") {
			// Simple extraction of members array
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "\"") && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "members") {
					// Extract quoted paths
					for _, part := range strings.Split(line, "\"") {
						part = strings.TrimSpace(part)
						if part != "" && !strings.ContainsAny(part, "[]=#,") {
							if _, err := os.Stat(filepath.Join(rootDir, part)); err == nil {
								addComponent(filepath.Base(part), part+"/")
							}
						}
					}
				}
			}
		}
	}

	// JS/TS workspaces (package.json "workspaces")
	if data, err := os.ReadFile(filepath.Join(rootDir, "package.json")); err == nil {
		var pkg map[string]interface{}
		if json.Unmarshal(data, &pkg) == nil {
			if ws, ok := pkg["workspaces"]; ok {
				var patterns []string
				switch v := ws.(type) {
				case []interface{}:
					for _, p := range v {
						if s, ok := p.(string); ok {
							patterns = append(patterns, s)
						}
					}
				case map[string]interface{}:
					// Yarn v1 style: { "packages": ["..."] }
					if pkgs, ok := v["packages"]; ok {
						if arr, ok := pkgs.([]interface{}); ok {
							for _, p := range arr {
								if s, ok := p.(string); ok {
									patterns = append(patterns, s)
								}
							}
						}
					}
				}
				for _, pattern := range patterns {
					matches, _ := filepath.Glob(filepath.Join(rootDir, pattern))
					for _, m := range matches {
						rel, _ := filepath.Rel(rootDir, m)
						if rel != "" && rel != "." {
							info, err := os.Stat(m)
							if err == nil && info.IsDir() {
								addComponent(filepath.Base(rel), rel+"/")
							}
						}
					}
				}
			}
		}
	}

	// Java Maven modules (pom.xml <modules>)
	if data, err := os.ReadFile(filepath.Join(rootDir, "pom.xml")); err == nil {
		content := string(data)
		// Simple XML extraction - find <module>...</module> tags
		for {
			start := strings.Index(content, "<module>")
			if start < 0 {
				break
			}
			content = content[start+8:]
			end := strings.Index(content, "</module>")
			if end < 0 {
				break
			}
			module := strings.TrimSpace(content[:end])
			content = content[end+9:]
			if module != "" {
				if _, err := os.Stat(filepath.Join(rootDir, module)); err == nil {
					addComponent(filepath.Base(module), module+"/")
				}
			}
		}
	}

	// Gradle subprojects (settings.gradle)
	for _, settingsFile := range []string{"settings.gradle", "settings.gradle.kts"} {
		if data, err := os.ReadFile(filepath.Join(rootDir, settingsFile)); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "include") {
					// Extract quoted project names like ':subproject'
					for _, part := range strings.Split(line, "'") {
						part = strings.TrimSpace(part)
						part = strings.TrimPrefix(part, ":")
						if part != "" && !strings.ContainsAny(part, "()=,") {
							dir := strings.ReplaceAll(part, ":", "/")
							if _, err := os.Stat(filepath.Join(rootDir, dir)); err == nil {
								addComponent(filepath.Base(dir), dir+"/")
							}
						}
					}
				}
			}
		}
	}

	// C# solution files (.sln)
	slnFiles, _ := filepath.Glob(filepath.Join(rootDir, "*.sln"))
	for _, slnFile := range slnFiles {
		if data, err := os.ReadFile(slnFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "Project(") && strings.Contains(line, ".csproj") {
					// Extract project path from: Project("...") = "Name", "path/to/proj.csproj", "..."
					parts := strings.Split(line, "\"")
					for _, part := range parts {
						if strings.HasSuffix(part, ".csproj") || strings.HasSuffix(part, ".fsproj") {
							dir := filepath.Dir(part)
							if dir != "." && dir != "" {
								dir = strings.ReplaceAll(dir, "\\", "/")
								if _, err := os.Stat(filepath.Join(rootDir, dir)); err == nil {
									addComponent(filepath.Base(dir), dir+"/")
								}
							}
						}
					}
				}
			}
		}
	}

	// Dart/Flutter Melos workspaces (melos.yaml)
	if data, err := os.ReadFile(filepath.Join(rootDir, "melos.yaml")); err == nil {
		inPackages := false
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "packages:" {
				inPackages = true
				continue
			}
			if inPackages {
				if !strings.HasPrefix(trimmed, "-") && trimmed != "" {
					break // End of packages list
				}
				if strings.HasPrefix(trimmed, "- ") {
					pattern := strings.TrimPrefix(trimmed, "- ")
					pattern = strings.TrimSpace(pattern)
					matches, _ := filepath.Glob(filepath.Join(rootDir, pattern))
					for _, m := range matches {
						rel, _ := filepath.Rel(rootDir, m)
						if info, err := os.Stat(m); err == nil && info.IsDir() {
							// Verify it's a Dart package (has pubspec.yaml)
							if _, err := os.Stat(filepath.Join(m, "pubspec.yaml")); err == nil {
								addComponent(filepath.Base(rel), rel+"/")
							}
						}
					}
				}
			}
		}
	}

	// Phase 2: Directory scanning for build files in common locations
	buildFiles := []string{
		"go.mod", "package.json", "Cargo.toml", "pom.xml",
		"build.gradle", "build.gradle.kts", "pyproject.toml",
		"setup.py", "Gemfile", "mix.exs", "build.sbt",
		"CMakeLists.txt", "composer.json", "pubspec.yaml",
	}

	scanPatterns := []string{"services", "cmd", "apps", "packages", "libs", "modules", "internal"}
	for _, dir := range scanPatterns {
		fullPath := filepath.Join(rootDir, dir)
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || excludeDirs[entry.Name()] {
				continue
			}
			subPath := filepath.Join(dir, entry.Name())
			for _, bf := range buildFiles {
				if _, err := os.Stat(filepath.Join(rootDir, subPath, bf)); err == nil {
					addComponent(entry.Name(), subPath+"/")
					break
				}
			}
		}
	}

	// Phase 3: Go cmd/ pattern (directories with main.go)
	cmdDir := filepath.Join(rootDir, "cmd")
	if entries, err := os.ReadDir(cmdDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			mainPath := filepath.Join(cmdDir, entry.Name(), "main.go")
			if _, err := os.Stat(mainPath); err == nil {
				addComponent(entry.Name(), "cmd/"+entry.Name()+"/")
			}
		}
	}

	// Phase 3b: Flutter/Dart apps (pubspec.yaml + lib/ at root)
	pubspecPath := filepath.Join(rootDir, "pubspec.yaml")
	if _, err := os.Stat(pubspecPath); err == nil {
		libDir := filepath.Join(rootDir, "lib")
		if _, err := os.Stat(libDir); err == nil {
			// Root is a Flutter/Dart project - extract name from pubspec
			if data, err := os.ReadFile(pubspecPath); err == nil {
				name := ""
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "name:") {
						name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
						break
					}
				}
				if name != "" {
					addComponent(name, ".")
				}
			}
		}
	}

	// Phase 4: Directories with Dockerfiles
	entries, err := os.ReadDir(rootDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || excludeDirs[entry.Name()] {
				continue
			}
			dockerPath := filepath.Join(rootDir, entry.Name(), "Dockerfile")
			if _, err := os.Stat(dockerPath); err == nil {
				addComponent(entry.Name(), entry.Name()+"/")
			}
		}
	}

	// Phase 5: Root directory itself if it has a build file and no other components found
	if len(components) == 0 {
		for _, bf := range buildFiles {
			if _, err := os.Stat(filepath.Join(rootDir, bf)); err == nil {
				// Root has a build file - will be handled by caller as fallback
				break
			}
		}
	}

	return components
}

// DetectLanguages scans the root directory for language indicator files
func DetectLanguages(rootDir string) []string {
	indicators := map[string][]string{
		"Go":         {"go.mod", "go.work"},
		"Java":       {"pom.xml", "build.gradle", "build.gradle.kts"},
		"Python":     {"pyproject.toml", "setup.py", "requirements.txt", "Pipfile"},
		"Rust":       {"Cargo.toml"},
		"Ruby":       {"Gemfile"},
		"JavaScript": {"package.json"},
		"TypeScript": {"tsconfig.json"},
		"C#":         {},
		"C/C++":      {"CMakeLists.txt"},
		"PHP":        {"composer.json"},
		"Elixir":     {"mix.exs"},
		"Scala":      {"build.sbt"},
		"Dart":       {"pubspec.yaml"},
	}

	// Glob-based indicators
	globIndicators := map[string]string{
		"C#":   "*.csproj",
		"Ruby": "*.gemspec",
	}

	var detected []string
	seen := make(map[string]bool)

	// Check file-based indicators
	for lang, files := range indicators {
		for _, f := range files {
			if _, err := os.Stat(filepath.Join(rootDir, f)); err == nil {
				if !seen[lang] {
					detected = append(detected, lang)
					seen[lang] = true
				}
				break
			}
		}
	}

	// Check glob-based indicators
	for lang, pattern := range globIndicators {
		if seen[lang] {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(rootDir, pattern))
		if len(matches) > 0 {
			detected = append(detected, lang)
			seen[lang] = true
		}
		// Also check one level deep
		matches, _ = filepath.Glob(filepath.Join(rootDir, "*", pattern))
		if len(matches) > 0 && !seen[lang] {
			detected = append(detected, lang)
			seen[lang] = true
		}
	}

	// Check for .sln files (C#)
	if !seen["C#"] {
		matches, _ := filepath.Glob(filepath.Join(rootDir, "*.sln"))
		if len(matches) > 0 {
			detected = append(detected, "C#")
		}
	}

	return detected
}

//go:build mage
// +build mage

package main

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

var Default = Build

// ================================
// Public targets
// ================================

// Builds for GOOS/GOARCH or host if unset
func Build() error {
	goos := getenv("GOOS", runtime.GOOS)
	goarch := getenv("GOARCH", runtime.GOARCH)
	return build(goos, goarch)
}

// Builds every supported platform
func All() error {
	for _, t := range targets() {
		if err := build(t.os, t.arch); err != nil {
			return err
		}
	}
	return nil
}

// Builds all and zips each with www/
// releaseVersion should not include 'v' prefix
// releaseVersion should be empty for non-release builds
func Release(ctx context.Context, releaseVersion string) error {
	if err := allRelease(releaseVersion); err != nil {
		return err
	}

	fmt.Println("Packaging release zips...")

	for _, t := range targets() {
		name := binName(t.os, t.arch, releaseVersion)
		binPath := filepath.Join("build", name)

		zipName := fmt.Sprintf("joepoints-v%s-%s-%s.zip", releaseVersion, t.os, t.arch)
		zipPath := filepath.Join("build", zipName)

		if err := zipRelease(zipPath, binPath); err != nil {
			return err
		}

		os.Remove(binPath)

		fmt.Println("Created", zipName)
	}

	return nil
}

func Clean() error {
	return os.RemoveAll("build")
}

// ================================
// Build logic
// ================================

type target struct {
	os   string
	arch string
}

func targets() []target {
	return []target{
		{"linux", "amd64"},
		{"linux", "386"},
		{"linux", "arm64"},

		{"windows", "amd64"},
		{"windows", "386"},
		{"windows", "arm64"},

		{"darwin", "amd64"},
		{"darwin", "arm64"},
	}
}

// Builds every supported platform for release
func allRelease(releaseVersion string) error {
	for _, t := range targets() {
		if err := build(t.os, t.arch); err != nil {
			return err
		}
		os.Rename(filepath.Join("build", binName(t.os, t.arch, "")), filepath.Join("build", binName(t.os, t.arch, releaseVersion)))
	}
	return nil
}

func build(goos, goarch string) error {
	fmt.Printf("Building joepoints (%s/%s)\n", goos, goarch)

	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}

	output := filepath.Join("build", binName(goos, goarch, ""))

	cmd := exec.Command(
		"go", "build",
		"-trimpath",
		"-ldflags=-s -w",
		"-o", output,
		"./cmd/joepoints",
	)

	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+goos,
		"GOARCH="+goarch,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func binName(goos, goarch, releaseVersion string) string {

	name := ""

	if releaseVersion == "" {
		name = fmt.Sprintf("joepoints-%s-%s", goos, goarch)
	} else {
		name = fmt.Sprintf("joepoints-v%s-%s-%s", releaseVersion, goos, goarch)
	}

	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// ================================
// Zip packaging
// ================================

func zipRelease(zipPath, binaryPath string) error {
	zf, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	defer zw.Close()

	// add binary
	if err := addFile(zw, binaryPath, filepath.Base(binaryPath)); err != nil {
		return err
	}

	// add www directory
	return filepath.Walk("www", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, _ := filepath.Rel(".", path)
		return addFile(zw, path, rel)
	})
}

func addFile(zw *zip.Writer, srcPath, zipPath string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w, err := zw.Create(zipPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, f)
	return err
}

// ================================
// Helpers
// ================================

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

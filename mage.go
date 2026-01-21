//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
)

var Default = Build

// Build compiles the joepoints binary
func Build() error {
	fmt.Println("Building joepoints...")

	cmd := exec.Command(
		"go", "build",
		"-o", "build/joepoints",
		"./cmd/joepoints",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

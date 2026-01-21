//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
)

var Default = Build

func Build() error {
	fmt.Println("Building joepoints...")

	output := "build/joepoints"
	if os.PathSeparator == '\\' { // Windows
		output += ".exe"
	}

	cmd := exec.Command(
		"go", "build",
		"-o", output,
		"./cmd/joepoints",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

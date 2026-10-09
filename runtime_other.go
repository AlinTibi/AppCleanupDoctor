//go:build !windows

package main

import (
	"errors"
	"fmt"
)

func checkRuntime() error      { return errors.New("App Cleanup Doctor requires Windows 10/11 x64") }
func showStartupError(e error) { fmt.Println(e) }

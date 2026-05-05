// Package util contains some helper functions
package util

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

func UsageFunc(commandName, positionalArgsName, flagHelpOutput, description string) func() {
	return func() {
		if positionalArgsName != "" && flagHelpOutput != "" {
			fmt.Printf("Usage: %s [%s] [OPTIONS]\n", commandName, positionalArgsName)
		} else if positionalArgsName != "" {
			fmt.Printf("Usage: %s [%s]\n", commandName, positionalArgsName)
		} else if flagHelpOutput != "" {
			fmt.Printf("Usage: %s [OPTIONS]\n", commandName)
		} else {
			fmt.Printf("Usage: %s\n", commandName)
		}

		if description != "" {
			fmt.Println("\nDescription: ")
			fmt.Println("  ", description)
		}
		if flagHelpOutput != "" {
			fmt.Println("\nOptions: ")
			fmt.Println(flagHelpOutput)
		}
	}
}

// CheckErr exits the program with a non-zero status when err is not nil.
// pflag.ErrHelp is treated specially and exits cleanly without printing an error.
func CheckErr(err error) {
	if err != nil {
		returnCode := 0
		if !errors.Is(err, pflag.ErrHelp) {
			// no need to print to error message for the above
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			returnCode = -1
		}
		os.Exit(returnCode)
	}
}

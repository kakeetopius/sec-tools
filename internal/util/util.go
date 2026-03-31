// Package util contains some helper functions
package util

import (
	"fmt"
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

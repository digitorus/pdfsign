package cli

import (
	"fmt"
	"os"
)

func Usage() {
	fmt.Printf("Usage: %s <command> [options] <args>\n\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  sign    Sign a PDF file")
	fmt.Println("  verify  Verify a PDF signature")
	fmt.Println("")
	fmt.Printf("Use '%s <command> -h' for command-specific help\n", os.Args[0])
	osExit(1)
}

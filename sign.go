package main

import (
	"fmt"
	"os"

	"github.com/digitorus/pdfsign/cli"
)

func main() {
	if len(os.Args) < 2 {
		cli.Usage()
	}

	switch os.Args[1] {
	case "sign":
		cli.SignCommand()
	case "verify":
		cli.VerifyCommand()
	case "-h", "--help", "help":
		cli.Usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		cli.Usage()
	}
}

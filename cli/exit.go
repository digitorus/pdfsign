package cli

import "os"

// Patchable os.Exit for testing
var osExit = os.Exit

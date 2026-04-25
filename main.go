package main

import (
	"fmt"
	"io"
	"os"

	"masktokens/internal/masker"
)

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "msk: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(masker.Mask(string(input)))
}

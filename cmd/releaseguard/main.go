package main

import (
	"fmt"
	"os"

	"github.com/peasant-labs/redact/internal/releaseguard"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: releaseguard title|tag VALUE")
		os.Exit(2)
	}
	var output string
	var err error
	switch os.Args[1] {
	case "title":
		output, err = releaseguard.VersionFromTitle(os.Args[2])
	case "tag":
		var kind releaseguard.Kind
		var base string
		kind, base, err = releaseguard.ClassifyTag(os.Args[2])
		output = string(kind) + " " + base
	default:
		err = fmt.Errorf("unknown releaseguard operation %q; use title or tag", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(output)
}

// Command jwks2pem writes the signing keys of a JWKS as PEM public keys, for
// verifiers that read keys only from files, not from a JWKS URL.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "jwks2pem: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	url := flag.String("url", "", "JWKS URL (required)")
	out := flag.String("out", "", "directory to write 1.pem .. N.pem into (required)")
	slots := flag.Int("slots", 0, "number of PEM files; more signing keys than this is an error (required)")
	cacert := flag.String("cacert", "", "CA certificate to trust for the URL, instead of the system's")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		printVersion()
		return nil
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q: every value is given with a flag", flag.Arg(0))
	}
	if *url == "" || *out == "" || *slots < 1 {
		flag.Usage()
		return errors.New("-url, -out and -slots are required")
	}

	body, err := fetch(*url, *cacert)
	if err != nil {
		return err
	}
	keys, err := signingKeys(body)
	if err != nil {
		return fmt.Errorf("%s: %w", *url, err)
	}
	files, err := slotFiles(keys, *slots)
	if err != nil {
		return fmt.Errorf("%s: %w", *url, err)
	}
	written, err := writeFiles(*out, files)
	for _, path := range written {
		fmt.Println(path)
	}
	return err
}

package main

import (
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sassoftware/relic/lib/authenticode"
	"io"
	"os"
	"slices"
)

//nolint:unused
var skipCheck = map[string]bool{
	"msvcp140.dll":               true,
	"vcruntime140.dll":           true,
	"vcruntime140_1.dll":         true,
	"vccorlib140.dll":            true,
	"css-html-validator-x64.dll": true,
	"node64.exe":                 true,
	"pcre.dll":                   true,
	"zlib1.dll":                  true,
}

// getRootCertPool returns a root CA pool built from the certificate in the
// R3CSR45CROSS2020 environment variable. When the env var is unset it falls
// back to the system pool.
func getRootCertPool() (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	pem := os.Getenv("R3CSR45CROSS2020")
	if pem == "" {
		fmt.Fprintln(os.Stderr, "R3CSR45CROSS2020 variable not set")
	} else {
		if !roots.AppendCertsFromPEM([]byte(pem)) {
			return nil, errors.New("failed to parse R3CSR45CROSS2020 certificate")
		}
	}
	return roots, nil
}

// (EXE, DLL) and validates that it is signed by Emurasoft, Inc. with a valid
// X.509 certificate chain. Returns an error describing what failed, or nil if the signature is valid.
func ValidatePESignature(r io.ReadSeeker) error {
	sigs, err := authenticode.VerifyPE(r, false)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(sigs) == 0 {
		return errors.New("PE file has no signatures")
	}

	roots, err := getRootCertPool()
	if err != nil {
		return err
	}

	for i, sig := range sigs {
		if sig.Certificate == nil {
			return errors.Errorf("signature %d has no certificate", i)
		}
		if err := sig.VerifyChain(roots, nil, x509.ExtKeyUsageCodeSigning); err != nil {
			return errors.WithMessagef(err, "signature %d: verify chain", i)
		}
		if err := validateSubject(sig.Certificate); err != nil {
			return errors.WithMessagef(err, "signature %d", i)
		}
	}

	return nil
}

// ValidateMSISignature verifies the Authenticode signature of an MSI file and
// validates the full X.509 certificate chain. Returns an error describing what failed, or nil if the signature is valid.
func ValidateMSISignature(r io.ReaderAt) error {
	sig, err := authenticode.VerifyMSI(r, false)
	if err != nil {
		return errors.WithStack(err)
	}

	if sig.Certificate == nil {
		return errors.New("MSI signature has no certificate")
	}

	roots, err := getRootCertPool()
	if err != nil {
		return err
	}

	if err := sig.VerifyChain(roots, nil, x509.ExtKeyUsageCodeSigning); err != nil {
		return errors.WithMessage(err, "verify chain")
	}

	if err := validateSubject(sig.Certificate); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// validateSubject checks that the signing certificate's Subject fields match
// the expected values for Emurasoft, Inc.
func validateSubject(cert *x509.Certificate) error {
	if !slices.Contains(cert.Subject.Organization, "Emurasoft, Inc.") {
		return errors.New("not signed by Emurasoft, Inc.")
	}
	if cert.Subject.CommonName != "Emurasoft, Inc." {
		return errors.Errorf("unexpected CommonName: %s", cert.Subject.CommonName)
	}
	if !slices.Contains(cert.Subject.Province, "Washington") {
		return errors.Errorf("unexpected State/Province: %v", cert.Subject.Province)
	}
	if !slices.Contains(cert.Subject.Country, "US") {
		return errors.Errorf("unexpected Country: %v", cert.Subject.Country)
	}
	return nil
}

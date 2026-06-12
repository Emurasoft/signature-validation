package main

import (
	"crypto/x509"
	"github.com/pkg/errors"
	"github.com/sassoftware/relic/lib/authenticode"
	"io"
	"slices"
)

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

	roots, err := x509.SystemCertPool()
	if err != nil {
		return errors.WithStack(err)
	}

	for i, sig := range sigs {
		if sig.Certificate == nil {
			return errors.Errorf("signature %d has no certificate", i)
		}
		if err := sig.VerifyChain(roots, nil, x509.ExtKeyUsageCodeSigning); err != nil {
			return errors.WithStack(err)
		}
		if !slices.Contains(sig.Certificate.Subject.Organization, "Emurasoft, Inc.") {
			return errors.Errorf("signature %d not signed by Emurasoft, Inc.", i)
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

	roots, err := x509.SystemCertPool()
	if err != nil {
		return errors.WithStack(err)
	}

	if err := sig.VerifyChain(roots, nil, x509.ExtKeyUsageCodeSigning); err != nil {
		return errors.WithStack(err)
	}

	if !slices.Contains(sig.Certificate.Subject.Organization, "Emurasoft, Inc.") {
		return errors.New("MSI not signed by Emurasoft, Inc.")
	}

	return nil
}

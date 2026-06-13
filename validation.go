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

var filesToCheck = map[string]bool{
	`mui\1028\emedloc.dll`:                  true,
	`mui\1029\emedloc.dll`:                  true,
	`mui\1031\emedloc.dll`:                  true,
	`mui\1033\emedloc.dll`:                  true,
	`mui\1036\emedloc.dll`:                  true,
	`mui\1040\emedloc.dll`:                  true,
	`mui\1041\emedloc.dll`:                  true,
	`mui\1042\emedloc.dll`:                  true,
	`mui\1043\emedloc.dll`:                  true,
	`mui\2052\emedloc.dll`:                  true,
	`mui\2057\emedloc.dll`:                  true,
	`mui\3082\emedloc.dll`:                  true,
	`PlugIns\CommitList.dll`:                true,
	`PlugIns\Explorer.dll`:                  true,
	`PlugIns\OpenDocuments.dll`:             true,
	`PlugIns\Projects.dll`:                  true,
	`PlugIns\Search.dll`:                    true,
	`PlugIns\Snippets.dll`:                  true,
	`PlugIns\WebPreview.dll`:                true,
	`PlugIns\WordComplete.dll`:              true,
	`PlugIns\WordCount.dll`:                 true,
	`PlugIns\mui\1028\CommitList_loc.dll`:   true,
	`PlugIns\mui\1028\Projects_loc.dll`:     true,
	`PlugIns\mui\1028\Snippets_loc.dll`:     true,
	`PlugIns\mui\1028\WordComplete_loc.dll`: true,
	`PlugIns\mui\1029\CommitList_loc.dll`:   true,
	`PlugIns\mui\1029\Projects_loc.dll`:     true,
	`PlugIns\mui\1029\Snippets_loc.dll`:     true,
	`PlugIns\mui\1029\WordComplete_loc.dll`: true,
	`PlugIns\mui\1031\CommitList_loc.dll`:   true,
	`PlugIns\mui\1031\Projects_loc.dll`:     true,
	`PlugIns\mui\1031\Snippets_loc.dll`:     true,
	`PlugIns\mui\1031\WordComplete_loc.dll`: true,
	`PlugIns\mui\1033\CommitList_loc.dll`:   true,
	`PlugIns\mui\1033\Projects_loc.dll`:     true,
	`PlugIns\mui\1033\Snippets_loc.dll`:     true,
	`PlugIns\mui\1033\WordComplete_loc.dll`: true,
	`PlugIns\mui\1036\CommitList_loc.dll`:   true,
	`PlugIns\mui\1036\Projects_loc.dll`:     true,
	`PlugIns\mui\1036\Snippets_loc.dll`:     true,
	`PlugIns\mui\1036\WordComplete_loc.dll`: true,
	`PlugIns\mui\1040\CommitList_loc.dll`:   true,
	`PlugIns\mui\1040\Projects_loc.dll`:     true,
	`PlugIns\mui\1040\Snippets_loc.dll`:     true,
	`PlugIns\mui\1040\WordComplete_loc.dll`: true,
	`PlugIns\mui\1041\CommitList_loc.dll`:   true,
	`PlugIns\mui\1041\Projects_loc.dll`:     true,
	`PlugIns\mui\1041\Snippets_loc.dll`:     true,
	`PlugIns\mui\1041\WordComplete_loc.dll`: true,
	`PlugIns\mui\1042\CommitList_loc.dll`:   true,
	`PlugIns\mui\1042\Projects_loc.dll`:     true,
	`PlugIns\mui\1042\Snippets_loc.dll`:     true,
	`PlugIns\mui\1042\WordComplete_loc.dll`: true,
	`PlugIns\mui\1043\CommitList_loc.dll`:   true,
	`PlugIns\mui\1043\Projects_loc.dll`:     true,
	`PlugIns\mui\1043\Snippets_loc.dll`:     true,
	`PlugIns\mui\1043\WordComplete_loc.dll`: true,
	`PlugIns\mui\2052\CommitList_loc.dll`:   true,
	`PlugIns\mui\2052\Projects_loc.dll`:     true,
	`PlugIns\mui\2052\Snippets_loc.dll`:     true,
	`PlugIns\mui\2052\WordComplete_loc.dll`: true,
	`PlugIns\mui\2057\CommitList_loc.dll`:   true,
	`PlugIns\mui\2057\Projects_loc.dll`:     true,
	`PlugIns\mui\2057\Snippets_loc.dll`:     true,
	`PlugIns\mui\2057\WordComplete_loc.dll`: true,
	`PlugIns\mui\3082\CommitList_loc.dll`:   true,
	`PlugIns\mui\3082\Projects_loc.dll`:     true,
	`PlugIns\mui\3082\Snippets_loc.dll`:     true,
	`PlugIns\mui\3082\WordComplete_loc.dll`: true,
	`ee128.dll`:                             true,
	`ee256.dll`:                             true,
	`ee512.dll`:                             true,
	`EEAdmin.exe`:                           true,
	`EECommon.dll`:                          true,
	`EEMacro.dll`:                           true,
	`emedcfd.dll`:                           true,
	`emedcfg.dll`:                           true,
	`emeddlgs.dll`:                          true,
	`emeddlgt.dll`:                          true,
	`emedhtml.exe`:                          true,
	`EmEditor.exe`:                          true,
	`emedres.dll`:                           true,
	`emedtray.exe`:                          true,
	`emeduwp.dll`:                           true,
	`emedws.exe`:                            true,
	`emonig.dll`:                            true,
	`emregexp.dll`:                          true,
	`emuchardet.dll`:                        true,
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
	} else if !roots.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("failed to parse R3CSR45CROSS2020 certificate")
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

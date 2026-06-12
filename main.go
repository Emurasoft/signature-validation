package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/playwright-community/playwright-go"
)

// ClickEmEditorDownload navigates to https://www.emeditor.com/,
// clicks the "Download Now" span, and returns the new URL.
func ClickEmEditorDownload(page playwright.Page) (string, error) {
	if _, err := page.Goto("https://www.emeditor.com/download/"); err != nil {
		return "", errors.Errorf("failed to navigate to emeditor.com: %w", err)
	}

	// Get the URL on the install link
	href, err := page.Locator("a[aria-label='Download Desktop Installer directly']").GetAttribute("href")
	if err != nil {
		return "", errors.Errorf("failed to read href for 'Download Desktop Installer directly': %w", err)
	}
	if href == "" {
		return "", errors.Errorf("'Download Desktop Installer directly' link has no href")
	}

	// After navigation completes, return the current page URL.
	return href, nil
}

// GetDownloadLink clicks on the Download Now button and returns the location of the redirect.
func GetDownloadLink() (string, error) {
	pw, err := playwright.Run()
	if err != nil {
		return "", errors.Errorf("could not start Playwright: %w", err)
	}
	defer func() {
		if err := pw.Stop(); err != nil {
			fmt.Println(err)
		}
	}()

	browser, err := pw.Chromium.Launch()
	if err != nil {
		return "", errors.Errorf("could not launch browser: %w", err)
	}
	defer func() {
		if err := browser.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	page, err := browser.NewPage()
	if err != nil {
		return "", errors.Errorf("could not create page: %w", err)
	}

	// Run the download click flow; ignore the URL, only surface errors.
	return ClickEmEditorDownload(page)
}

var client = &http.Client{
	Timeout: 20 * time.Second,
}

// downloadToTemp downloads a file from the given URL to a temporary directory.
// It returns the path to the temporary file.
func downloadToTemp(url string) (string, error) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "download-")
	if err != nil {
		return "", errors.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		if err := tmpFile.Close(); err != nil {
			panic(err)
		}
	}()

	// Get the data
	resp, err := client.Get(url)
	if err != nil {
		return "", errors.Errorf("failed to download file: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			panic(err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("bad status: %s", resp.Status)
	}

	// Write the body to file
	if _, err = io.Copy(tmpFile, resp.Body); err != nil {
		return "", errors.Errorf("failed to save file: %w", err)
	}

	return tmpFile.Name(), nil
}

// SignatureInfo represents the output of Get-AuthenticodeSignature.
type SignatureInfo struct {
	SignerCertificate SignerCertificate
	Status            int
	StatusMessage     string
	Path              string
}

// SignerCertificate represents the signer certificate information.
type SignerCertificate struct {
	NotAfter  time.Time
	NotBefore time.Time
	RawData   []byte
	Subject   SubjectInfo
}

func (sc *SignerCertificate) UnmarshalJSON(b []byte) error {
	type Alias SignerCertificate
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(sc),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return errors.WithStack(err)
	}

	if len(sc.RawData) > 0 {
		subject, err := ExtractSubjectInfo(sc.RawData)
		if err != nil {
			return errors.Errorf("failed to extract subject info: %w", err)
		}
		sc.Subject = subject
	}

	return nil
}

// SubjectInfo represents the parsed Subject field of a certificate.
type SubjectInfo struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Locality           string
	State              string
	Country            string
}

func (s *SubjectInfo) UnmarshalJSON(b []byte) error {
	// We don't need to unmarshal from string anymore if we have RawData,
	// but the JSON still contains the Subject string. We can ignore it or
	// keep it if we want to support both.
	// For now, let's just do nothing here and let RawData handle it.
	return nil
}

// ExtractSubjectInfo extracts SubjectInfo from raw certificate bytes.
func ExtractSubjectInfo(rawData []byte) (SubjectInfo, error) {
	cert, err := x509.ParseCertificate(rawData)
	if err != nil {
		return SubjectInfo{}, errors.WithStack(err)
	}

	info := SubjectInfo{
		CommonName: cert.Subject.CommonName,
	}
	if len(cert.Subject.Organization) > 0 {
		info.Organization = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		info.OrganizationalUnit = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Locality) > 0 {
		info.Locality = cert.Subject.Locality[0]
	}
	if len(cert.Subject.Province) > 0 {
		info.State = cert.Subject.Province[0]
	}
	if len(cert.Subject.Country) > 0 {
		info.Country = cert.Subject.Country[0]
	}

	return info, nil
}

// getSignatureInfo calls Get-AuthenticodeSignature and returns the parsed info.
func getSignatureInfo(filePath string) (SignatureInfo, error) {
	cmdStr := fmt.Sprintf(
		"Get-AuthenticodeSignature '%s' | Select-Object @{Name='SignerCertificate'; Expression={$_.SignerCertificate | Select-Object NotAfter, NotBefore, Subject, RawData}}, Status, StatusMessage | ConvertTo-Json",
		filePath,
	)

	cmd := exec.Command("pwsh",
		"-NoProfile",
		"-NonInteractive",
		"-Command", cmdStr,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return SignatureInfo{}, errors.Errorf(
			"powershell command failed: %w; stdout/stderr:\n%s",
			err, string(out),
		)
	}

	var info SignatureInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return SignatureInfo{}, errors.Errorf("failed to parse json: %w; raw:\n%s", err, string(out))
	}

	return info, nil
}

type ValidationResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

// validateSignature validates the signature information.
func validateSignature(info SignatureInfo) ValidationResult {
	if info.Status != 0 {
		return ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("invalid signature status: %s (status code: %d)", info.StatusMessage, info.Status),
		}
	}

	subject := info.SignerCertificate.Subject
	if subject.CommonName != "Emurasoft, Inc." {
		return ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("unexpected Common Name: %s", subject.CommonName),
		}
	}

	if subject.Organization != "Emurasoft, Inc." {
		return ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("unexpected Organization: %s", subject.Organization),
		}
	}

	if subject.State != "Washington" {
		return ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("unexpected State: %s", subject.State),
		}
	}

	if subject.Country != "US" {
		return ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("unexpected Country: %s", subject.Country),
		}
	}

	return ValidationResult{
		Valid: true,
	}
}

func mainWithError() (*ValidationResult, error) {
	fmt.Fprintf(os.Stderr, "Getting download link\n")

	downloadURL, err := GetDownloadLink()
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Downloading from %s\n", downloadURL)

	path, err := downloadToTemp(downloadURL)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "File downloaded to: %s\n", path)

	info, err := getSignatureInfo(path)
	if err != nil {
		return nil, err
	}

	result := validateSignature(info)

	// Clean up
	if err := os.Remove(path); err != nil {
		return nil, errors.WithStack(err)
	}
	return &result, nil
}

type ProgramOutput struct {
	Result *ValidationResult `json:"result,omitempty"`
	Error  string            `json:"error,omitempty"`
	Time   time.Time         `json:"time"`
}

func main() {
	result, err := mainWithError()
	output := ProgramOutput{
		Time: time.Now().UTC(),
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %+v\n", output.Error)
	} else {
		output.Result = result
	}

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode output: %+v\n", err)
		os.Exit(1)
	}

	if output.Error != "" {
		os.Exit(1)
	}
}

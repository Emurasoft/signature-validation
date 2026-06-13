package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mholt/archives"
	"github.com/pkg/errors"
	"github.com/playwright-community/playwright-go"
	"golang.org/x/net/html"
)

// ClickEmEditorDownload navigates to https://www.emeditor.com/,
// clicks the "Download Now" span, and returns the new URL.
func ClickEmEditorDownload(page playwright.Page) (string, error) {
	if _, err := page.Goto("https://www.emeditor.com/download/"); err != nil {
		return "", errors.WithMessage(err, "failed to navigate to emeditor.com")
	}

	// Get the URL on the install link
	href, err := page.Locator("a[aria-label='Download Desktop Installer directly']").GetAttribute("href")
	if err != nil {
		return "", errors.WithMessage(err, "failed to read href for 'Download Desktop Installer directly'")
	}
	if href == "" {
		return "", errors.New("'Download Desktop Installer directly' link has no href")
	}

	// After navigation completes, return the current page URL.
	return href, nil
}

// GetInstallerDownloadLink clicks on the Download Now button and returns the location of the redirect.
func GetInstallerDownloadLink() (string, error) {
	pw, err := playwright.Run()
	if err != nil {
		return "", errors.WithMessage(err, "could not start Playwright")
	}
	defer func() {
		if err := pw.Stop(); err != nil {
			fmt.Println(err)
		}
	}()

	browser, err := pw.Chromium.Launch()
	if err != nil {
		return "", errors.WithMessage(err, "could not launch browser")
	}
	defer func() {
		if err := browser.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	page, err := browser.NewPage()
	if err != nil {
		return "", errors.WithMessage(err, "could not create page")
	}

	// Run the download click flow; ignore the URL, only surface errors.
	return ClickEmEditorDownload(page)
}

// GetPortableDownloadLink scrapes the EmEditor download page for the Portable Version
// download link and returns its href URL.
func GetPortableDownloadLink() (string, error) {
	resp, err := client.Get("https://www.emeditor.com/download/")
	if err != nil {
		return "", errors.WithMessage(err, "failed to fetch download page")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("bad status: %s", resp.Status)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return "", errors.WithMessage(err, "failed to parse HTML")
	}

	href, found := findPortableLink(doc)
	if !found {
		return "", errors.New("portable version link not found on download page")
	}

	return href, nil
}

// findPortableLink traverses the HTML tree looking for the anchor element
// that links to the Portable Version download page.
func findPortableLink(n *html.Node) (string, bool) {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, attr := range n.Attr {
			if attr.Key == "href" && strings.Contains(attr.Val, "/en/downloads/latest/portable") {
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode && strings.Contains(n.FirstChild.Data, "Portable Version") {
					return attr.Val, true
				}
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if href, found := findPortableLink(c); found {
			return href, found
		}
	}

	return "", false
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
		return "", errors.WithMessage(err, "failed to create temp file")
	}
	defer tmpFile.Close()

	// Get the data
	resp, err := client.Get(url)
	if err != nil {
		return "", errors.WithMessage(err, "failed to download file")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("bad status: %s", resp.Status)
	}

	// Write the body to file
	if _, err = io.Copy(tmpFile, resp.Body); err != nil {
		return "", errors.WithMessage(err, "failed to save file: %w")
	}

	return tmpFile.Name(), nil
}

// ValidateZipArchive extracts all files from a ZIP archive at the given path,
// validating the Authenticode signature of every .exe and .dll file (excluding
// those in skipCheck). It returns a ValidationResult summarizing the findings.
func ValidateZipArchive(path string) (*ValidationResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer f.Close()

	ctx := context.Background()
	var failures []string

	err = archives.Zip{}.Extract(ctx, f, func(ctx context.Context, info archives.FileInfo) error {
		name := info.NameInArchive

		// Skip unknown files
		if !filesToCheck[filepath.Base(name)] {
			return nil
		}

		// Open the file from the archive
		rc, err := info.Open()
		if err != nil {
			return errors.WithMessagef(err, "failed to open %s", name)
		}
		defer rc.Close()

		// Read content into memory (ValidatePESignature needs io.ReadSeeker)
		content, err := io.ReadAll(rc)
		if err != nil {
			return errors.WithMessagef(err, "failed to read %s", name)
		}

		// Validate PE signature
		reader := bytes.NewReader(content)
		if err := ValidatePESignature(reader); err != nil {
			msg := fmt.Sprintf("%s: %v", name, err)
			fmt.Fprintf(os.Stderr, "FAIL: %s\n", msg)
			failures = append(failures, msg)
			return nil // keep processing the rest
		}

		fmt.Fprintf(os.Stderr, "OK: %s\n", name)
		return nil
	})
	if err != nil {
		return nil, errors.WithMessage(err, "failed to extract archive")
	}

	result := &ValidationResult{Valid: true}
	if len(failures) > 0 {
		result.Valid = false
		result.Reason = strings.Join(failures, "; ")
	}

	return result, nil
}

type ValidationResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

type Result struct {
	InstallerResult *ValidationResult `json:"installer_result,omitempty"`
	PortableResult  *ValidationResult `json:"portable_result,omitempty"`
}

func mainWithError() (*Result, error) {
	// --- Installer (MSI) check ---
	fmt.Fprintf(os.Stderr, "Getting installer download link\n")

	installerURL, err := GetInstallerDownloadLink()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Installer download link: %s\n", installerURL)
	fmt.Fprintf(os.Stderr, "Downloading installer from %s\n", installerURL)

	installerPath, err := downloadToTemp(installerURL)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Installer downloaded to: %s\n", installerPath)

	installerFile, err := os.Open(installerPath)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to open installer file")
	}

	installerResult := &ValidationResult{Valid: true}
	fmt.Fprintf(os.Stderr, "Validating installer MSI signature\n")
	if err := ValidateMSISignature(installerFile); err != nil {
		installerResult.Valid = false
		installerResult.Reason = fmt.Sprintf("installer MSI: %v", err)
		fmt.Fprintf(os.Stderr, "FAIL: %s\n", installerResult.Reason)
	} else {
		fmt.Fprintf(os.Stderr, "OK: installer signature valid\n")
	}
	installerFile.Close()

	// --- Portable (ZIP) check ---
	fmt.Fprintf(os.Stderr, "Getting portable download link\n")

	downloadURL, err := GetPortableDownloadLink()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Portable download link: %s\n", downloadURL)
	fmt.Fprintf(os.Stderr, "Downloading portable from %s\n", downloadURL)

	path, err := downloadToTemp(downloadURL)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Portable downloaded to: %s\n", path)

	portableResult, err := ValidateZipArchive(path)
	if err != nil {
		return nil, err
	}
	if !portableResult.Valid {
		fmt.Fprintf(os.Stderr, "FAIL: portable ZIP: %s\n", portableResult.Reason)
	} else {
		fmt.Fprintf(os.Stderr, "OK: portable signatures valid\n")
	}

	return &Result{
		InstallerResult: installerResult,
		PortableResult:  portableResult,
	}, nil
}

type ProgramOutput struct {
	*Result
	Error string    `json:"error,omitempty"`
	Time  time.Time `json:"time"`
}

func main() {
	result, err := mainWithError()
	output := ProgramOutput{
		Time: time.Now().UTC(),
	}
	if err != nil {
		output.Error = err.Error()
		fmt.Fprintf(os.Stderr, "error: %+v\n", err)
	} else {
		// If validation failed, do not return non-zero code to ensure issue is created.
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

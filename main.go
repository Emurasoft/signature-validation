package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

type ValidationResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
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

	f, err := os.Open(path)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer f.Close()

	var result ValidationResult
	if err := ValidatePESignature(f); err != nil {
		result = ValidationResult{
			Valid:  false,
			Reason: err.Error(),
		}
	} else {
		result = ValidationResult{Valid: true}
	}

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
		output.Error = err.Error()
		fmt.Fprintf(os.Stderr, "error: %+v\n", err)
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

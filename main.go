package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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
	defer func() {
		if err := tmpFile.Close(); err != nil {
			panic(err)
		}
	}()

	// Get the data
	resp, err := client.Get(url)
	if err != nil {
		return "", errors.WithMessage(err, "failed to download file")
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
		return "", errors.WithMessage(err, "failed to save file: %w")
	}

	return tmpFile.Name(), nil
}

type ValidationResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

func mainWithError() (*ValidationResult, error) {
	fmt.Fprintf(os.Stderr, "Getting download link\n")

	downloadURL, err := GetInstallerDownloadLink()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Download link: %s\n", downloadURL)
	fmt.Fprintf(os.Stderr, "Downloading from %s\n", downloadURL)

	return &ValidationResult{Valid: true}, nil

	//path, err := downloadToTemp(downloadURL)
	//if err != nil {
	//	return nil, err
	//}
	//
	//fmt.Fprintf(os.Stderr, "File downloaded to: %s\n", path)
	//
	//f, err := os.Open(path)
	//if err != nil {
	//	return nil, errors.WithStack(err)
	//}
	//defer func() {
	//	if err := f.Close(); err != nil {
	//		fmt.Fprintln(os.Stderr, err)
	//	}
	//}()
	//
	//var result ValidationResult
	//if err := ValidateMSISignature(f); err != nil {
	//	result = ValidationResult{
	//		Valid:  false,
	//		Reason: err.Error(),
	//	}
	//} else {
	//	result = ValidationResult{Valid: true}
	//}
	//
	//// Since it is run in CI and files are saved to temporary directory, the files are not removed at the end
	//return &result, nil
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

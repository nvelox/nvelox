package errorhtml

import (
	"strings"
	"testing"
)

func TestDefaultErrorPage_CommonCodes(t *testing.T) {
	codes := []int{400, 403, 404, 405, 408, 413, 429, 500, 502, 503, 504}

	for _, code := range codes {
		page := DefaultErrorPage(code)
		html := string(page)

		if !strings.Contains(html, "<!DOCTYPE html>") {
			t.Errorf("code %d: missing DOCTYPE", code)
		}
		if !strings.Contains(html, "<title>") {
			t.Errorf("code %d: missing title", code)
		}
		if !strings.Contains(html, "nvelox") {
			t.Errorf("code %d: missing nvelox footer", code)
		}
		if len(page) < 500 {
			t.Errorf("code %d: page too small (%d bytes)", code, len(page))
		}
	}
}

func TestDefaultErrorPage_404_HasSearchIcon(t *testing.T) {
	page := string(DefaultErrorPage(404))
	if !strings.Contains(page, "circle") { // search icon has circle
		t.Error("404 page should use search icon")
	}
	if !strings.Contains(page, "#7f8c8d") { // gray color
		t.Error("404 page should use gray color")
	}
}

func TestDefaultErrorPage_429_HasClockIcon(t *testing.T) {
	page := string(DefaultErrorPage(429))
	if !strings.Contains(page, "polyline") { // clock icon has polyline
		t.Error("429 page should use clock icon")
	}
}

func TestDefaultErrorPage_403_HasLockIcon(t *testing.T) {
	page := string(DefaultErrorPage(403))
	if !strings.Contains(page, "path") { // lock icon has path element
		t.Error("403 page should use lock icon")
	}
}

func TestDefaultErrorPage_502_HasServerIcon(t *testing.T) {
	page := string(DefaultErrorPage(502))
	if !strings.Contains(page, "rect") { // server icon has rect
		t.Error("502 page should use server icon")
	}
}

func TestDefaultErrorPage_UnknownCode(t *testing.T) {
	page := string(DefaultErrorPage(418))
	if !strings.Contains(page, "418") {
		t.Error("should contain status code")
	}
}

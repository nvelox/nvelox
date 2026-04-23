package errorhtml

import (
	"fmt"
	"net/http"
	"strings"
)

// DefaultErrorPage returns a styled HTML error page for the given status code.
func DefaultErrorPage(statusCode int) []byte {
	title := http.StatusText(statusCode)
	if title == "" {
		title = "Error"
	}

	color := "#e74c3c" // red
	icon := errorIcon
	switch {
	case statusCode == 429:
		color = "#f39c12" // orange
		icon = throttleIcon
	case statusCode == 502 || statusCode == 503 || statusCode == 504:
		color = "#e67e22" // dark orange
		icon = serverIcon
	case statusCode == 403:
		color = "#c0392b" // dark red
		icon = lockIcon
	case statusCode == 404:
		color = "#7f8c8d" // gray
		icon = notFoundIcon
	case statusCode >= 400 && statusCode < 500:
		color = "#e74c3c"
	}

	description := errorDescription(statusCode)

	html := strings.ReplaceAll(pageTemplate, "{{STATUS}}", fmt.Sprintf("%d", statusCode))
	html = strings.ReplaceAll(html, "{{TITLE}}", title)
	html = strings.ReplaceAll(html, "{{COLOR}}", color)
	html = strings.ReplaceAll(html, "{{ICON}}", icon)
	html = strings.ReplaceAll(html, "{{DESCRIPTION}}", description)

	return []byte(html)
}

func errorDescription(code int) string {
	switch code {
	case 400:
		return "The server could not understand the request."
	case 403:
		return "You don't have permission to access this resource."
	case 404:
		return "The page you're looking for doesn't exist."
	case 405:
		return "This request method is not allowed for this resource."
	case 408:
		return "The server timed out waiting for the request."
	case 413:
		return "The request body is too large."
	case 429:
		return "You're sending too many requests. Please slow down."
	case 500:
		return "Something went wrong on our end."
	case 502:
		return "The server received an invalid response from an upstream server."
	case 503:
		return "The service is temporarily unavailable. Please try again later."
	case 504:
		return "The upstream server didn't respond in time."
	default:
		return "An unexpected error occurred."
	}
}

const errorIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`

const throttleIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`

const serverIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`

const lockIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`

const notFoundIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/></svg>`

const pageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{STATUS}} {{TITLE}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#f5f6fa;color:#2c3e50;display:flex;align-items:center;justify-content:center;
min-height:100vh;padding:20px}
.container{text-align:center;max-width:520px}
.icon{color:{{COLOR}};margin-bottom:24px}
.status{font-size:72px;font-weight:700;color:{{COLOR}};line-height:1;margin-bottom:8px}
.title{font-size:24px;font-weight:600;margin-bottom:12px;color:#2c3e50}
.description{font-size:16px;color:#7f8c8d;line-height:1.5;margin-bottom:32px}
.divider{width:60px;height:3px;background:{{COLOR}};margin:0 auto 24px;border-radius:2px}
.footer{font-size:12px;color:#bdc3c7}
.footer a{color:#95a5a6;text-decoration:none}
</style>
</head>
<body>
<div class="container">
<div class="icon">{{ICON}}</div>
<div class="status">{{STATUS}}</div>
<div class="title">{{TITLE}}</div>
<div class="divider"></div>
<div class="description">{{DESCRIPTION}}</div>
<div class="footer">nvelox</div>
</div>
</body>
</html>`

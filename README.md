# PhishGuard

PhishGuard is a lightweight browser-based phishing URL scanner that helps users evaluate whether a URL looks suspicious based on common phishing indicators.

It checks for patterns such as:
- HTTP instead of HTTPS
- Direct IP address usage
- Misleading `@` symbols
- Suspicious keywords like `login`, `verify`, `password`, `account`, and `secure`
- Long URLs
- Multiple subdomains
- Punycode-encoded domains
- Unusual ports

The app assigns a risk score from 0 to 100 and classifies the result as Low Risk, Medium Risk, or High Risk.

## Features

- URL risk scanning
- Real-time phishing indicator analysis
- Score-based risk classification
- Recent scan history saved in browser storage
- Simple front-end interface with no backend required

## Project Structure

```text
Phish_Guard/
├── index.html          # Main UI
├── style.css           # Styling and layout
├── script.js           # URL analysis logic and scan behavior
├── README.md           # Project documentation
```

## How It Works

1. Enter a website URL into the scanner.
2. The app validates the URL and normalizes it.
3. It checks common phishing patterns and calculates a score.
4. Results are displayed with explanations for each detected indicator.

## Run Locally

Because this is a simple front-end project, you can run it by opening `index.html` directly in a browser.

## Tech Stack

- HTML5
- CSS3
- JavaScript

## Disclaimer

This project is intended for educational and awareness purposes only. It analyzes URL characteristics heuristically and should not be treated as a definitive phishing detection system.

## License

This project is provided for learning and experimentation.

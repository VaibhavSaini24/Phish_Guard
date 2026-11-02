
const form = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const resultSection = document.getElementById("resultSection");
const riskLabel = document.getElementById("riskLabel");
const riskScore = document.getElementById("riskScore");
const scoreBar = document.getElementById("scoreBar");
const indicatorList = document.getElementById("indicatorList");
const scannedUrl = document.getElementById("scannedUrl");
const historyList = document.getElementById("historyList");

const STORAGE_KEY = "phishguard-history";

// Check whether a hostname is an IPv4 address.
function isIPAddress(hostname) {
    const parts = hostname.split(".");

    return parts.length === 4 &&
        parts.every(part =>
            /^\d+$/.test(part) &&
            Number(part) >= 0 &&
            Number(part) <= 255
        );
}

// Analyze URL characteristics.
function analyzeURL(input) {
    let url;

    try {
        const cleaned = input.trim();
        const normalized = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(cleaned)
            ? cleaned
            : "https://" + cleaned;

        url = new URL(normalized);

        if (!["http:", "https:"].includes(url.protocol)) {
            throw new Error("Only HTTP and HTTPS URLs are supported.");
        }

        if (!url.hostname) {
            throw new Error("Invalid hostname.");
        }

    } catch (error) {
        throw new Error("Please enter a valid HTTP or HTTPS URL.");
    }

    const host = url.hostname.toLowerCase();
    const fullURL = url.href.toLowerCase();

    let score = 0;
    const indicators = [];

    function addIndicator(name, points, detected, explanation) {
        if (detected) {
            score += points;
        }

        indicators.push({
            name,
            points: detected ? points : 0,
            detected,
            explanation
        });
    }

    // 1. HTTPS check
    addIndicator(
        "HTTPS Encryption",
        15,
        url.protocol === "http:",
        url.protocol === "http:"
            ? "The URL uses HTTP instead of HTTPS."
            : "The URL uses HTTPS. This does not guarantee legitimacy."
    );

    // 2. IP address check
    addIndicator(
        "IP Address Usage",
        25,
        isIPAddress(host),
        "The website uses a direct IP address instead of a domain name."
    );

    // 3. @ symbol check
    addIndicator(
        "Misleading @ Symbol",
        25,
        url.username !== "" || url.password !== "",
        "The URL contains user information before the hostname."
    );

    // 4. Suspicious keywords
    const suspiciousWords = [
        "login",
        "verify",
        "password",
        "secure",
        "account",
        "update",
        "banking",
        "signin"
    ];

    const foundWords = suspiciousWords.filter(word =>
        new RegExp(`(^|[^a-z])${word}([^a-z]|$)`, "i").test(fullURL)
    );

    addIndicator(
        "Suspicious Keywords",
        15,
        foundWords.length > 0,
        foundWords.length
            ? "Found: " + foundWords.join(", ")
            : "No configured suspicious keywords found."
    );

    // 5. URL length
    addIndicator(
        "Unusually Long URL",
        10,
        fullURL.length > 100,
        "Long URLs can hide misleading paths or information."
    );

    // 6. Multiple subdomains
    const domainParts = host.split(".");

    addIndicator(
        "Multiple Subdomains",
        10,
        !isIPAddress(host) && domainParts.length >= 5,
        "The hostname contains many domain components."
    );

    // 7. Punycode domain
    addIndicator(
        "Punycode Domain",
        25,
        host.split(".").some(part => part.startsWith("xn--")),
        "The domain contains encoded international characters."
    );

    // 8. Unusual port
    addIndicator(
        "Unusual Port",
        10,
        url.port !== "",
        "The URL specifies a non-default port."
    );

    score = Math.min(score, 100);

    let risk;

    if (score >= 50) {
        risk = "High Risk";
    } else if (score >= 20) {
        risk = "Medium Risk";
    } else {
        risk = "Low Risk";
    }

    return {
        url: url.href,
        score,
        risk,
        indicators,
        date: new Date().toLocaleString()
    };
}

// Display scan results.
function displayResults(result) {
    resultSection.classList.remove("hidden");

    riskLabel.textContent = result.risk;
    riskScore.textContent = result.score;
    scannedUrl.textContent = "Scanned URL: " + result.url;

    scoreBar.style.width = result.score + "%";

    let color = "#4ade80";

    if (result.score >= 50) {
        color = "#ef4444";
    } else if (result.score >= 20) {
        color = "#f59e0b";
    }

    riskLabel.style.color = color;
    scoreBar.style.background = color;

    document.querySelector(".score-circle").style.borderColor = color;

    indicatorList.replaceChildren();

    result.indicators.forEach(item => {
        const row = document.createElement("div");
        row.className = "indicator";

        const description = document.createElement("span");
        description.textContent =
            (item.detected ? "⚠️ " : "✓ ") +
            item.name + " — " + item.explanation;

        const points = document.createElement("strong");
        points.className = item.detected
            ? "detected"
            : "not-detected";

        points.textContent = item.detected
            ? "+" + item.points
            : "Clear";

        row.append(description, points);
        indicatorList.appendChild(row);
    });
}

// Save the last 10 scans.
function saveHistory(result) {
    let history = getHistory();

    history.unshift({
        url: result.url,
        score: result.score,
        risk: result.risk,
        date: result.date
    });

    history = history.slice(0, 10);

    localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(history)
    );

    displayHistory();
}

function getHistory() {
    try {
        const history = JSON.parse(
            localStorage.getItem(STORAGE_KEY) || "[]"
        );

        return Array.isArray(history) ? history : [];
    } catch {
        return [];
    }
}

// Display recent scans.
function displayHistory() {
    const history = getHistory();

    historyList.replaceChildren();

    if (history.length === 0) {
        const message = document.createElement("p");
        message.className = "muted";
        message.textContent = "No scans yet.";
        historyList.appendChild(message);
        return;
    }

    history.forEach(item => {
        const row = document.createElement("div");
        row.className = "history-item";

        const title = document.createElement("strong");
        title.textContent = item.risk + " — " + item.score + "/100";

        const url = document.createElement("div");
        url.textContent = item.url;

        const date = document.createElement("small");
        date.textContent = item.date;

        row.append(title, url, date);
        historyList.appendChild(row);
    });
}

// Main scan button.
form.addEventListener("submit", function(event) {
    event.preventDefault();

    try {
        const result = analyzeURL(urlInput.value);

        displayResults(result);
        saveHistory(result);

    } catch (error) {
        alert(error.message);
    }
});

// Example URL buttons.
document.querySelectorAll(".example").forEach(button => {
    button.addEventListener("click", function() {
        urlInput.value = this.dataset.url;
        form.requestSubmit();
    });
});

// Clear scan history.
document.getElementById("clearHistory")
    .addEventListener("click", function() {

        localStorage.removeItem(STORAGE_KEY);
        displayHistory();
    });

// Load history when application opens.
displayHistory();

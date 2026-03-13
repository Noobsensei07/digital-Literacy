require('dotenv').config();
const crypto = require('crypto');
const pdf = require('pdf-parse');
const axios = require('axios');
const Tesseract = require('tesseract.js');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');

// ═══════════════════════════════════════════════════════════════════════════
// Helper: Google Safe Browsing Check
// ═══════════════════════════════════════════════════════════════════════════
const checkGoogleSafeBrowsing = async (url) => {
    const apiKey = process.env.SAFE_BROWSING_API_KEY;
    if (!apiKey) return null; // Gracefully pass

    try {
        const body = {
            client: {
                clientId: "dlip_app",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };

        const response = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, body);
        const data = response.data;
        if (data && data.matches && data.matches.length > 0) {
            return "Danger: Google Safe Browsing explicitly flagged this URL as malware/phishing.";
        }
    } catch (e) {
        console.error("Safe Browsing API Error:", e.message);
    }
    return null;
};

// Utility to sleep for polling if needed
const delay = ms => new Promise(res => setTimeout(res, ms));

// ═══════════════════════════════════════════════════════════════════════════
// PHISHING / SUSPICIOUS DOMAIN BLOCKLIST (120+)
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// NEW: User-Requested Heuristics Arrays
// ═══════════════════════════════════════════════════════════════════════════
const suspiciousTLDs = [
    '.xyz', '.top', '.club', '.work', '.click', '.link', '.info', '.online',
    '.site', '.live', '.store', '.icu', '.buzz', '.gq', '.ml', '.ga', '.cf',
    '.tk', '.pw', '.cc', '.ws', '.space', '.fun', '.monster', '.rest'
];

const phishingKeywords = [
    'login', 'verify', 'update', 'confirm', 'secure', 'account', 'signin',
    'billing', 'suspend', 'locked', 'alert', 'urgent', 'expired', 'renew',
    'password', 'credential', 'authenticate', 'validate', 'recover'
];

const knownFakeDomains = [
    'secure-login-verify.xyz', 'verification-support.com', 'bank-crew-mvgr.space',
    'paypa1.com', 'g00gle.com', 'faceb00k.com', 'amaz0n.com',
    'micr0soft.com', 'app1e.com', 'netf1ix.com', 'lnstagram.com'
];

// ═══════════════════════════════════════════════════════════════════════════
// STEP 1: analyzeUrlHeuristics
// ═══════════════════════════════════════════════════════════════════════════
function analyzeUrlHeuristics(targetUrl) {
    let status = "Safe";
    let details = [];

    // 1. IP addresses hiding as domains
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/;
    if (ipRegex.test(targetUrl)) {
        status = "Fraud";
        details.push("URL uses a raw IP address instead of a domain name.");
    }

    // 2. Unusually long URLs (length > 75)
    if (targetUrl.length > 75) {
        if (status !== "Fraud") status = "Caution";
        details.push("URL is unusually long (over 75 characters).");
    }

    try {
        const parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
        const hostname = parsedUrl.hostname.toLowerCase();
        const pathLower = parsedUrl.pathname.toLowerCase() + parsedUrl.search.toLowerCase();

        // 3. Matches in knownFakeDomains
        for (const domain of knownFakeDomains) {
            if (hostname === domain || hostname.endsWith('.' + domain)) {
                status = "Fraud";
                details.push(`Domain matches known fake domain blocklist: ${domain}`);
            }
        }

        // 3.5. Brand spoofing checks
        const strictBrands = ['paypal', 'apple', 'amazon', 'netflix', 'microsoft', 'google'];
        for (const brand of strictBrands) {
            if (hostname.includes(brand)) {
                // If it contains a brand word, but does NOT end with ".brand.com" or exactly equal "brand.com"
                if (!(hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`))) {
                    status = "Fraud";
                    details.push(`High risk spoofing detected: Domain impersonates ${brand.toUpperCase()}.`);
                }
            }
        }

        // 4. Matches in suspiciousTLDs
        for (const tld of suspiciousTLDs) {
            if (hostname.endsWith(tld)) {
                if (status !== "Fraud") status = "Caution";
                details.push(`Uses a suspicious TLD: ${tld}`);
            }
        }

        // 5. Matches in phishingKeywords
        for (const kw of phishingKeywords) {
            if (pathLower.includes(kw) || hostname.includes(kw)) {
                if (status !== "Fraud") status = "Caution";
                details.push(`Contains phishing-related keyword: ${kw}`);
            }
        }
    } catch (_) {
        if (status !== "Fraud") status = "Caution";
        details.push("URL format is malformed or invalid.");
    }

    // HTTPS Security Check
    if (targetUrl.startsWith('http://')) {
        if (status !== "Fraud") status = "Caution";
        details.push("Connection is unencrypted (HTTP). Real services always use HTTPS.");
    }

    if (details.length === 0) {
        details.push("Passed basic heuristic checks.");
    }

    return { status, details };
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN: scanUrl — Implementation of custom 3-Step logic
// ═══════════════════════════════════════════════════════════════════════════
const scanUrl = async (req, res) => {
    try {
        const { url: targetUrl } = req.body;
        if (!targetUrl) {
            return res.status(400).json({ error: "No URL provided." });
        }

        // Step A: Run through heuristics
        const heuristicResult = analyzeUrlHeuristics(targetUrl);

        // Instant return if Fraud
        if (heuristicResult.status === "Fraud") {
            return res.json({
                status: "Fraud",
                color: "Red",
                details: heuristicResult.details,
                source: "Heuristics"
            });
        }

        // Fire both API requests in parallel if keys exist
        const apiKey = process.env.VT_API_KEY;
        const urlId = Buffer.from(targetUrl)
            .toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');

        let vtPromise = Promise.resolve(null);
        if (apiKey) {
            vtPromise = axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
                headers: { 'x-apikey': apiKey }
            }).catch(e => {
                // If it's a 404, it means VirusTotal hasn't seen this URL before. We return null so heuristics operate alone.
                if (e.response && e.response.status !== 404) {
                     console.error("VT Error:", e.message);
                }
                return null;
            });
        } else {
            heuristicResult.details.push("VirusTotal skipped: Missing API Key.");
        }

        const sbPromise = checkGoogleSafeBrowsing(targetUrl);

        // Await both simultaneously
        const [vtResponse, sbWarning] = await Promise.all([vtPromise, sbPromise]);

        // Integrate Google Safe Browsing Results
        if (sbWarning) {
            heuristicResult.status = "Fraud";
            heuristicResult.details.push(sbWarning);
        }

        // Integrate VirusTotal Results
        if (vtResponse && vtResponse.data) {
            const stats = vtResponse.data.data.attributes.last_analysis_stats;
            const maliciousCount = stats.malicious + stats.suspicious;
            const totalScans = maliciousCount + stats.harmless + stats.undetected;

            if (maliciousCount > 0) {
                heuristicResult.status = "Fraud";
                heuristicResult.details.push(`VirusTotal flagged this: ${maliciousCount} out of ${totalScans} engines reported it as malicious.`);
            } else if (stats.harmless > 0 && heuristicResult.status !== "Fraud") {
                heuristicResult.status = "Safe";
                heuristicResult.details.push(`VirusTotal clean: ${stats.harmless} engines marked it safe.`);
            }
        }

        // Final Return Assembly
        const finalColor = heuristicResult.status === "Fraud" ? "Red"
                         : heuristicResult.status === "Caution" ? "Yellow"
                         : "Green";

        return res.json({
            status: heuristicResult.status,
            color: finalColor,
            details: heuristicResult.details,
            source: "Combined AI/Heuristic/API Analysis"
        });
    } catch (error) {
        console.error("Error in scan-url:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};

const scanFile = async (req, res) => {
    try {
        const file = req.file;
        if (!file) {
            return res.status(400).json({ error: "No document provided." });
        }

        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            return res.status(500).json({ error: "GEMINI_API_KEY not configured." });
        }

        let extractedText = "";
        const mimeType = file.mimetype;

        if (mimeType === 'application/pdf') {
            try {
                const pdfData = await pdf(file.buffer);
                extractedText = pdfData.text;
            } catch (err) {
                console.error("PDF Parse Error:", err);
                return res.status(400).json({ error: "Could not read PDF. It might be corrupted or encrypted." });
            }
        } else if (mimeType.startsWith('image/')) {
            try {
                // Run Tesseract OCR on the image buffer
                const result = await Tesseract.recognize(file.buffer, 'eng');
                extractedText = result.data.text;
            } catch (err) {
                console.error("OCR Error:", err);
                return res.status(400).json({ error: "Could not extract text from image." });
            }
        } else {
            return res.status(400).json({ error: "Unsupported file type. Please upload a PDF or an Image." });
        }

        if (!extractedText || extractedText.trim().length === 0) {
            return res.json({
                status: "Caution",
                color: "Yellow",
                reason: "Document appears to be empty or unreadable."
            });
        }

        // Send extracted text to Gemini
        const prompt = `
Analyze the following extracted text from a document/image for phishing, fake invoices, urgency scams, or malware delivery attempts.
Respond strictly in JSON format with three fields:
1. "status": strictly "Safe", "Caution", or "Fraud".
2. "color": strictly "Green" for Safe, "Yellow" for Caution, and "Red" for Fraud.
3. "details": An array of strings containing 1 to 3 concise bullet points explaining why, e.g. ["domain resembles bank.com", "suspicious sender"].

Extracted Text:
"${extractedText.substring(0, 10000).replace(/"/g, '\\"')}"
`;

        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: {
                    responseMimeType: "application/json",
                    temperature: 0.2
                }
            })
        });

        if (response.ok) {
            const data = await response.json();
            const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
            if (rawText) {
                try {
                    const parsed = JSON.parse(rawText);
                    let st = parsed.status || "Caution";
                    if (!["Safe", "Caution", "Fraud"].includes(st)) st = "Caution";

                    let clr = parsed.color || "Yellow";
                    if (!["Green", "Yellow", "Red"].includes(clr)) clr = "Yellow";

                    let det = parsed.details;
                    if (!Array.isArray(det)) det = parsed.reason ? [parsed.reason] : ["AI flagged potential issue."];

                    return res.json({
                        status: st,
                        color: clr,
                        details: det
                    });
                } catch (jsonErr) {
                    console.error("JSON parse error from Gemini inside scanFile");
                }
            }
        }
        
        return res.status(500).json({ error: "Failed to analyze document text." });

    } catch (error) {
        console.error("Error in scan-file:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};

module.exports = {
    scanUrl,
    scanFile
};

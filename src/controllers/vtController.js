require('dotenv').config();
const crypto = require('crypto');
const pdf = require('pdf-parse');
const axios = require('axios');

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
    // 1. IP addresses hiding as domains
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/;
    if (ipRegex.test(targetUrl)) {
        return { status: "Fraud", reason: "URL uses a raw IP address instead of a domain name." };
    }

    // 2. Unusually long URLs (length > 75)
    if (targetUrl.length > 75) {
        return { status: "Caution", reason: "URL is unusually long (over 75 characters)." };
    }

    try {
        const parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
        const hostname = parsedUrl.hostname.toLowerCase();
        const pathLower = parsedUrl.pathname.toLowerCase() + parsedUrl.search.toLowerCase();

        // 3. Matches in knownFakeDomains
        for (const domain of knownFakeDomains) {
            if (hostname === domain || hostname.endsWith('.' + domain)) {
                return { status: "Fraud", reason: `Domain matches known fake domain blocklist: ${domain}` };
            }
        }

        // 4. Matches in suspiciousTLDs
        for (const tld of suspiciousTLDs) {
            if (hostname.endsWith(tld)) {
                return { status: "Caution", reason: `Domain uses a suspicious TLD: ${tld}` };
            }
        }

        // 5. Matches in phishingKeywords
        for (const kw of phishingKeywords) {
            if (pathLower.includes(kw) || hostname.includes(kw)) {
                return { status: "Caution", reason: `URL contains phishing-related keyword: ${kw}` };
            }
        }
    } catch (_) {
        return { status: "Caution", reason: "URL format is malformed or invalid." };
    }

    return { status: "Safe", reason: "Passed basic heuristic checks." };
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
                classification: "Fraud",
                color: "Red",
                reason: heuristicResult.reason,
                source: "Heuristics"
            });
        }

        // Step B: Axios call to VirusTotal
        const apiKey = process.env.VT_API_KEY;
        if (!apiKey) {
            // Fallback to heuristics if no VT key
            return res.json({
                classification: heuristicResult.status,
                color: heuristicResult.status === "Caution" ? "Yellow" : "Green",
                reason: heuristicResult.reason + " (VirusTotal skipping due to missing API Key)",
                source: "Heuristics"
            });
        }

        try {
            // Encode URL to base64url format for VT v3 endpoint
            const urlId = Buffer.from(targetUrl)
                .toString('base64')
                .replace(/=/g, '')
                .replace(/\+/g, '-')
                .replace(/\//g, '_');

            const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
                headers: { 'x-apikey': apiKey }
            });

            // Step C: Parse last_analysis_stats
            const stats = vtResponse.data.data.attributes.last_analysis_stats;
            const maliciousCount = stats.malicious || 0;
            const suspiciousCount = stats.suspicious || 0;

            if (maliciousCount > 0 || suspiciousCount > 0) {
                return res.json({
                    classification: "Fraud",
                    color: "Red",
                    reason: `VirusTotal flagged this as malicious (${maliciousCount} malicious, ${suspiciousCount} suspicious).`,
                    stats: stats,
                    source: "VirusTotal"
                });
            } else {
                // If VT is clear, return the original heuristic result
                return res.json({
                    classification: heuristicResult.status,
                    color: heuristicResult.status === "Caution" ? "Yellow" : "Green",
                    reason: heuristicResult.reason + " (Also cleared by VirusTotal).",
                    stats: stats,
                    source: "VT + Heuristics"
                });
            }
        } catch (vtErr) {
            // VT Not Found (404) means the URL hasn't been scanned yet.
            // VT Quota exceeded (429) etc.
            if (vtErr.response && vtErr.response.status === 404) {
                 return res.json({
                    classification: heuristicResult.status,
                    color: heuristicResult.status === "Caution" ? "Yellow" : "Green",
                    reason: heuristicResult.reason + " (Not yet known in VirusTotal database).",
                    source: "Heuristics Fallback"
                 });
            }
            console.error("VT Axios Error:", vtErr.message);
            return res.json({
                classification: heuristicResult.status,
                color: heuristicResult.status === "Caution" ? "Yellow" : "Green",
                reason: heuristicResult.reason + " (VirusTotal lookup failed).",
                source: "Heuristics Fallback"
            });
        }
    } catch (error) {
        console.error("Error in scan-url:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};

const scanFile = async (req, res) => {
    try {
        // req.file is populated by multer
        const file = req.file;
        if (!file) {
            return res.status(400).json({ error: "No file provided." });
        }

        const apiKey = process.env.VT_API_KEY;
        if (!apiKey) {
            return res.status(500).json({ error: "VT_API_KEY not configured." });
        }

        // Calculate SHA-256 of the buffer
        const hash = crypto.createHash('sha256');
        hash.update(file.buffer);
        const fileHash = hash.digest('hex');

        // Check VT for this hash
        const getResponse = await fetch(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
            method: 'GET',
            headers: { 'x-apikey': apiKey }
        });

        if (!getResponse.ok) {
            if (getResponse.status === 404) {
                // Not found means VT has never seen it. Safe to assume safe or unknown.
                return res.json({
                    hash: fileHash,
                    classification: "Safe",
                    message: "File not found in VirusTotal database (0 malicious detections)."
                });
            }
            const errBody = await getResponse.text();
            console.error("VT File Error:", getResponse.status, errBody);
            return res.status(getResponse.status).json({ error: "Failed to check file hash against VirusTotal." });
        }

        const data = await getResponse.json();
        const stats = data.data.attributes.last_analysis_stats;

        const maliciousCount = stats.malicious || 0;
        const suspiciousCount = stats.suspicious || 0;

        let classification = "Safe";
        if (maliciousCount > 0) {
            classification = "Malicious";
        } else if (suspiciousCount > 0) {
            classification = "Suspicious";
        }

        return res.json({
            hash: fileHash,
            classification,
            stats,
            message: `VT reported ${maliciousCount} malicious votes for this file.`
        });

    } catch (error) {
        console.error("Error in scan-file:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};

const scanPdf = async (req, res) => {
    try {
        const file = req.file;
        if (!file) {
            return res.status(400).json({ error: "No PDF file provided." });
        }

        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            return res.status(500).json({ error: "GEMINI_API_KEY not configured." });
        }

        // 1. Extract text
        let dataBuffer = file.buffer;
        let pdfData;
        try {
            pdfData = await pdf(dataBuffer);
        } catch (pdfErr) {
            console.error("PDF Parse Error:", pdfErr);
            return res.status(400).json({ error: "Could not read PDF. File might be corrupted or encrypted." });
        }

        const extractedText = pdfData.text;
        if (!extractedText || extractedText.trim().length === 0) {
            return res.json({
                classification: "Caution",
                reason: "PDF appears to be empty or contains only images. Cannot verify contents."
            });
        }

        // 2. Ask Gemini
        const prompt = `
Analyze the following extracted text from a PDF document for phishing, fake invoices, scam language, or malware delivery attempts.
Respond in strict JSON format with two fields:
1. "classification": Must be exactly "Safe", "Caution", or "Fraud".
2. "reason": A single, concise sentence explaining why.

Extracted PDF Text:
"${extractedText.substring(0, 10000).replace(/"/g, '\\"')}" // limit to 10k chars
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
                    // Ensure it forces the 3-color system
                    let cl = parsed.classification || "Caution";
                    if (!["Safe", "Caution", "Fraud"].includes(cl)) cl = "Caution";

                    return res.json({
                        classification: cl,
                        reason: parsed.reason || "AI flagged potential issue."
                    });
                } catch (jsonErr) {
                    console.error("JSON parse error from Gemini inside scanPdf");
                }
            }
        }
        
        return res.status(500).json({ error: "Failed to analyze PDF text." });

    } catch (error) {
        console.error("Error in scan-pdf:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};

module.exports = {
    scanUrl,
    scanFile,
    scanPdf
};

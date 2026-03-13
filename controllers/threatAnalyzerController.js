require('dotenv').config();

// Helper to check Google Safe Browsing API
const safeBrowsingCheck = async (urls) => {
    if (!urls || urls.length === 0) return null;
    
    const apiKey = process.env.SAFE_BROWSING_API_KEY;
    if (!apiKey) {
        console.warn("SAFE_BROWSING_API_KEY not configured. Skipping URL check.");
        return null;
    }

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
                threatEntries: urls.map(url => ({ url }))
            }
        };

        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            const data = await response.json();
            if (data && data.matches && data.matches.length > 0) {
                return {
                    classification: "Malicious",
                    reason: "Warning: URL flagged by Google Safe Browsing as unsafe."
                };
            }
        }
    } catch (e) {
        console.error("Safe Browsing API Error:", e);
    }
    
    return null;
}

// Helper to check Gemini API for NLP analysis
const geminiCheck = async (text) => {
    if (!text || text.trim().length === 0) return null;

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        console.warn("GEMINI_API_KEY not configured. Skipping AI analysis.");
        return null; // Fallback
    }

    try {
        const prompt = `
Analyze the following notification text for social engineering, phishing, or scam attempts. 
Respond in strict JSON format with two fields:
1. "classification": Must be exactly "Safe", "Caution", or "Fraud".
2. "reason": A single, concise sentence explaining why.

Notification Text:
"${text.replace(/"/g, '\\"')}"
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
                    return parsed;
                } catch (jsonErr) {
                   console.error("Error parsing Gemini JSON:", jsonErr, rawText);
                }
            }
        }
    } catch (e) {
        console.error("Gemini API Request Error:", e.message || e);
    }

    return null;
}

const analyzeThreat = async (req, res) => {
    try {
        const { text, urls } = req.body;
        
        let classificationText = "Safe";
        let defaultReason = "No threats detected.";

        // 1. Safe Browsing Check (High Priority)
        if (urls && urls.length > 0) {
            const sbResult = await safeBrowsingCheck(urls);
            if (sbResult) {
                return res.json({
                    classification: sbResult.classification === "Malicious" ? "Fraud" : "Caution", // map Old SB to new system
                    reason: sbResult.reason
                });
            }
            defaultReason = "URL is unknown but not flagged by Safe Browsing.";
        }

        // 2. AI Text Analysis
        if (text) {
            const aiResult = await geminiCheck(text);
            if (aiResult) {
                let cl = aiResult.classification || "Caution";
                if (!["Safe", "Caution", "Fraud"].includes(cl)) cl = "Caution";
                return res.json({
                    classification: cl,
                    reason: aiResult.reason || "AI flagged potential issue."
                });
            }
        }

        // 3. Fallback
        res.json({
            classification: classificationText,
            reason: defaultReason
        });
        
    } catch (error) {
        console.error("Error in analyze-threat:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};

module.exports = {
    analyzeThreat
};

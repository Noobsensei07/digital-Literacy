require('dotenv').config();

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
            let rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
            if (rawText) {
                try {
                    // Strip markdown blocks if Gemini returned them
                    rawText = rawText.replace(/```json/g, "").replace(/```/g, "").trim();
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

        // 1. URL Analysis (Skip if handled by LinkAnalyzer frontend)
        if (urls && urls.length > 0) {
            // Note: In Phase 10, URL reputation is strictly handled in parallel via /scan-url in Flutter LinkAnalyzer.
            // We only process pure text logic in this fallback pipeline.
            defaultReason = "URL checked via background handler.";
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

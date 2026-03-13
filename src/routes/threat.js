const express = require('express');
const router = express.Router();
const multer = require('multer');
const { scanUrl, scanFile, scanPdf } = require('../controllers/vtController');

// Configure multer for memory storage
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const { analyzeThreat } = require('../controllers/threatAnalyzerController');

// POST /api/analyze-threat (Existing Gemini API NLP & SafeBrowsing endpoint)
router.post('/analyze-threat', analyzeThreat);

// POST /api/scan-url (3-step pipeline: Pattern → Blocklist → VirusTotal)
router.post('/scan-url', scanUrl);

// POST /api/scan-file (VirusTotal API v3 File Hash Scan)
router.post('/scan-file', upload.single('file'), scanFile);

// POST /api/scan-pdf (Extracts text and runs AI NLP for phishing invoices)
router.post('/scan-pdf', upload.single('file'), scanPdf);

module.exports = router;

require('dotenv').config();

const express = require('express');
const cors = require('cors');

// ── Route modules ───────────────────────────────────────────────────────────
const authRoutes = require('./routes/auth');
const questionRoutes = require('./routes/questions');
const assessmentRoutes = require('./routes/assessments');
const threatRoutes = require('./routes/threat');

// ── App setup ───────────────────────────────────────────────────────────────
const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Simple request logger
app.use((req, _res, next) => {
    console.log(`${new Date().toISOString()}  ${req.method}  ${req.originalUrl}`);
    next();
});

// ── Routes ─────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => {
    res.json({
        name: 'Digital Literacy App API',
        version: '1.0.0',
        endpoints: {
            auth: '/api/auth   (signup · login · profile)',
            questions: '/api/questions   (random · categories)',
            assessments: '/api/assessments   (submit · history)',
        },
    });
});

app.use('/api/auth', authRoutes);
app.use('/api/questions', questionRoutes);
app.use('/api/assessments', assessmentRoutes);
app.use('/api', threatRoutes); // Mounts /api/analyze-threat

// ── 404 catch-all ──────────────────────────────────────────────────────────
app.use((_req, res) => {
    res.status(404).json({ error: 'Route not found.' });
});

// ── Global error handler ───────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Something went wrong.' });
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`\n🚀  Server running on http://localhost:${PORT}\n`);
});

module.exports = app;

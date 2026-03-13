const express = require('express');
const supabase = require('../config/supabase');

const router = express.Router();

// ─── GET /api/questions/random ──────────────────────────────────────────────
// Query params:
//   ?category=Internet%20Safety   (optional — filter by category)
//   ?limit=10                     (optional — number of questions, default 5)
router.get('/random', async (req, res) => {
    try {
        const { category, limit } = req.query;
        const questionLimit = Math.min(parseInt(limit, 10) || 5, 50); // cap at 50

        let query = supabase.from('questions').select('*');

        // Filter by category if provided
        if (category) {
            query = query.eq('category', category);
        }

        // Supabase doesn't have a native random-order method,
        // so we fetch all matching rows and shuffle client-side.
        const { data, error } = await query;

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({ error: 'No questions found.' });
        }

        // Fisher-Yates shuffle
        const shuffled = [...data];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }

        const selected = shuffled.slice(0, questionLimit);

        // Strip correct_answer from the response so the client can't cheat
        const sanitized = selected.map(({ correct_answer, ...rest }) => rest);

        return res.status(200).json({
            count: sanitized.length,
            questions: sanitized,
        });
    } catch (err) {
        console.error('Questions fetch error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── GET /api/questions/categories ──────────────────────────────────────────
// Returns the distinct list of question categories.
router.get('/categories', async (_req, res) => {
    try {
        const { data, error } = await supabase
            .from('questions')
            .select('category');

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        const unique = [...new Set(data.map((q) => q.category))];
        return res.status(200).json({ categories: unique });
    } catch (err) {
        console.error('Categories fetch error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

module.exports = router;

const express = require('express');
const supabase = require('../config/supabase');
const requireAuth = require('../middleware/auth');
const { submitWithPythonScorer } = require('../controllers/scorerController');

const router = express.Router();

// ─── POST /api/assessments/submit ───────────────────────────────────────────
// Body: { answers: [{ question_id: "uuid", selected_answer: "text" }, ...] }
// Protected route — requires Bearer token.
router.post('/submit', requireAuth, async (req, res) => {
    try {
        const { answers } = req.body;

        if (!answers || !Array.isArray(answers) || answers.length === 0) {
            return res.status(400).json({
                error: 'Request body must include a non-empty "answers" array.',
            });
        }

        // 1. Fetch the correct answers for all submitted question IDs
        const questionIds = answers.map((a) => a.question_id);

        const { data: questions, error: fetchError } = await supabase
            .from('questions')
            .select('id, correct_answer, difficulty_weight')
            .in('id', questionIds);

        if (fetchError) {
            return res.status(500).json({ error: fetchError.message });
        }

        // Build a lookup map: question_id → { correct_answer, difficulty_weight }
        const questionMap = {};
        for (const q of questions) {
            questionMap[q.id] = {
                correct_answer: q.correct_answer,
                difficulty_weight: q.difficulty_weight ?? 1,
            };
        }

        // 2. Grade each answer (flat 2 points per correct answer)
        let totalScore = 0;
        const results = answers.map((a) => {
            const question = questionMap[a.question_id];
            if (!question) {
                return {
                    question_id: a.question_id,
                    correct: false,
                    message: 'Question not found.',
                };
            }

            const isCorrect =
                a.selected_answer?.trim().toLowerCase() ===
                question.correct_answer.trim().toLowerCase();

            if (isCorrect) {
                totalScore += 2;
            }

            return {
                question_id: a.question_id,
                selected_answer: a.selected_answer,
                correct_answer: question.correct_answer,
                correct: isCorrect,
                points: isCorrect ? 2 : 0,
            };
        });

        // 3. Insert assessment record
        const { error: insertError } = await supabase
            .from('assessments')
            .insert({
                user_id: req.user.id,
                total_score: totalScore,
            });

        if (insertError) {
            console.error('Assessment insert error:', insertError);
            return res.status(500).json({ error: 'Failed to save assessment.' });
        }

        // 4. Update the user's cumulative overall_score
        //    Fetch current score, add new score, update.
        const { data: userRow, error: userFetchError } = await supabase
            .from('users')
            .select('overall_score')
            .eq('id', req.user.id)
            .single();

        if (!userFetchError && userRow) {
            const newOverall = (userRow.overall_score || 0) + totalScore;

            await supabase
                .from('users')
                .update({ overall_score: newOverall })
                .eq('id', req.user.id);
        }

        return res.status(200).json({
            message: 'Assessment submitted successfully.',
            total_score: totalScore,
            total_questions: answers.length,
            correct_count: results.filter((r) => r.correct).length,
            results,
        });
    } catch (err) {
        console.error('Assessment submit error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── GET /api/assessments/history ───────────────────────────────────────────
// Returns the authenticated user's assessment history.
router.get('/history', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('assessments')
            .select('*')
            .eq('user_id', req.user.id)
            .order('timestamp', { ascending: false });

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        return res.status(200).json({ assessments: data });
    } catch (err) {
        console.error('Assessment history error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── POST /api/assessments/submit-scored ────────────────────────────────────
// Uses the Python scorer (scripts/scorer.py) for weighted score calculation.
// Body: { answers: [{ question_id: "uuid", selected_answer: "text" }, ...] }
router.post('/submit-scored', requireAuth, submitWithPythonScorer);

module.exports = router;

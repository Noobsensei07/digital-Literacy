const { spawn } = require('child_process');
const path = require('path');
const supabase = require('../config/supabase');

const SCORER_SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'scorer.py');

/**
 * Spawns the Python scorer process, pipes in the answers payload,
 * and resolves with the parsed JSON result.
 *
 * @param {Array} answers - Array of { question_score: 0|1, difficulty_weight: number }
 * @returns {Promise<{ final_score: number }>}
 */
function runPythonScorer(answers) {
    return new Promise((resolve, reject) => {
        const py = spawn('python', [SCORER_SCRIPT]);

        let stdout = '';
        let stderr = '';

        py.stdout.on('data', (chunk) => {
            stdout += chunk.toString();
        });

        py.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
        });

        py.on('close', (code) => {
            if (code !== 0) {
                return reject(
                    new Error(`Python scorer exited with code ${code}: ${stderr}`)
                );
            }
            try {
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (parseErr) {
                reject(new Error(`Failed to parse scorer output: ${stdout}`));
            }
        });

        py.on('error', (err) => {
            reject(new Error(`Failed to spawn Python process: ${err.message}`));
        });

        // Send the answers array as JSON to stdin, then close the stream
        py.stdin.write(JSON.stringify(answers));
        py.stdin.end();
    });
}

/**
 * Express handler: POST /api/assessments/submit-scored
 *
 * Body: {
 *   answers: [
 *     { question_id: "uuid", selected_answer: "text" },
 *     ...
 *   ]
 * }
 *
 * 1. Fetches correct answers from DB to grade each question (0 or 1).
 * 2. Passes the graded array to the Python scorer for weighted calculation.
 * 3. Saves the assessment and updates the user's overall_score.
 */
async function submitWithPythonScorer(req, res) {
    try {
        const { answers } = req.body;

        if (!answers || !Array.isArray(answers) || answers.length === 0) {
            return res.status(400).json({
                error: 'Request body must include a non-empty "answers" array.',
            });
        }

        // 1. Fetch correct answers & weights from the DB
        const questionIds = answers.map((a) => a.question_id);

        const { data: questions, error: fetchError } = await supabase
            .from('questions')
            .select('id, correct_answer, difficulty_weight')
            .in('id', questionIds);

        if (fetchError) {
            return res.status(500).json({ error: fetchError.message });
        }

        const questionMap = {};
        for (const q of questions) {
            questionMap[q.id] = {
                correct_answer: q.correct_answer,
                difficulty_weight: q.difficulty_weight ?? 1,
            };
        }

        // 2. Grade each answer → build payload for the Python scorer
        const scorerInput = answers.map((a) => {
            const question = questionMap[a.question_id];
            if (!question) {
                return { question_score: 0, difficulty_weight: 0 };
            }
            const isCorrect =
                a.selected_answer?.trim().toLowerCase() ===
                question.correct_answer.trim().toLowerCase();

            return {
                question_score: isCorrect ? 1 : 0,
                difficulty_weight: question.difficulty_weight,
            };
        });

        // 3. Run the Python scorer
        const scorerResult = await runPythonScorer(scorerInput);
        const totalScore = scorerResult.final_score;

        // 4. Save assessment record
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

        // 5. Update user's cumulative overall_score
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

        // 6. Build detailed results for the response
        const results = answers.map((a, i) => {
            const question = questionMap[a.question_id];
            return {
                question_id: a.question_id,
                selected_answer: a.selected_answer,
                correct_answer: question?.correct_answer ?? null,
                correct: scorerInput[i].question_score === 1,
                points: scorerInput[i].question_score * scorerInput[i].difficulty_weight,
            };
        });

        return res.status(200).json({
            message: 'Assessment submitted (Python scorer).',
            total_score: totalScore,
            total_questions: answers.length,
            correct_count: results.filter((r) => r.correct).length,
            results,
        });
    } catch (err) {
        console.error('Python scorer submit error:', err);
        return res.status(500).json({ error: err.message || 'Internal server error.' });
    }
}

module.exports = { submitWithPythonScorer, runPythonScorer };

const supabase = require('../config/supabase');

/**
 * Middleware: verifies the Bearer token via Supabase Auth.
 * On success, attaches the authenticated user to `req.user`.
 */
async function requireAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Missing or malformed Authorization header. Expected: Bearer <token>',
            });
        }

        const token = authHeader.split(' ')[1];

        const { data, error } = await supabase.auth.getUser(token);

        if (error || !data?.user) {
            return res.status(401).json({
                error: 'Invalid or expired token.',
            });
        }

        // Attach user info to the request for downstream handlers
        req.user = data.user;
        next();
    } catch (err) {
        console.error('Auth middleware error:', err);
        return res.status(500).json({ error: 'Internal authentication error.' });
    }
}

module.exports = requireAuth;

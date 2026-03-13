const express = require('express');
const supabase = require('../config/supabase');
const requireAuth = require('../middleware/auth');

const router = express.Router();

// ─── POST /api/auth/signup ──────────────────────────────────────────────────
router.post('/signup', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        // 1. Create account via Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signUp({
            email,
            password,
        });

        if (authError) {
            return res.status(400).json({ error: authError.message });
        }

        // 2. Insert a matching row into the public `users` table
        const { error: profileError } = await supabase
            .from('users')
            .insert({
                id: authData.user.id,
                email: authData.user.email,
            });

        if (profileError) {
            console.error('Profile insert error:', profileError);
            // The Auth account already exists; the profile row can be retried.
            // We still return success so the client knows sign-up went through.
        }

        return res.status(201).json({
            message: 'User created successfully.',
            user: {
                id: authData.user.id,
                email: authData.user.email,
            },
            session: authData.session,
        });
    } catch (err) {
        console.error('Signup error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── POST /api/auth/login ───────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password,
        });

        if (error) {
            return res.status(401).json({ error: error.message });
        }

        return res.status(200).json({
            message: 'Logged in successfully.',
            user: {
                id: data.user.id,
                email: data.user.email,
            },
            session: {
                access_token: data.session.access_token,
                refresh_token: data.session.refresh_token,
                expires_at: data.session.expires_at,
            },
        });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── GET /api/auth/profile ──────────────────────────────────────────────────
router.get('/profile', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (error) {
            return res.status(404).json({ error: 'User profile not found.' });
        }

        return res.status(200).json({ profile: data });
    } catch (err) {
        console.error('Profile fetch error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

module.exports = router;

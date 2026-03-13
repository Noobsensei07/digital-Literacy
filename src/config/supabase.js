const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
    console.error(
        '❌  Missing SUPABASE_URL or SUPABASE_ANON_KEY in .env file.\n' +
        '   Copy .env.example → .env and fill in your Supabase credentials.'
    );
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseAnonKey);

module.exports = supabase;

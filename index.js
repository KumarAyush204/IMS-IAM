// ### 1. Import Dependencies ###
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); // ⭐️ Changed
const cookieParser = require('cookie-parser');
require('dotenv').config();

// ### 2. App & Middleware Setup ###
const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser()); // Used to read the token from cookies

// ### 3. Database Connection Pool ###
const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});
console.log('✅ Database connection pool created.');

// ⭐️ New: Middleware to verify JWT and protect routes
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token; // Read token from the cookie

    if (!token) {
        return res.redirect('/login'); // If no token, user is not logged in
    }

    try {
        // Verify the token using the secret key
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach the user payload (id, name, email) to the request
        next(); // Proceed to the protected route
    } catch (err) {
        // If token is invalid or expired
        res.clearCookie('token');
        return res.redirect('/login');
    }
};

// --- Page Routes ---

app.get('/', (req, res) => {
    // If a valid token cookie exists, redirect to dashboard
    if (req.cookies.token) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/login', (req, res) => {
    res.render('login');
});

// --- API Endpoints ---

// POST /register (No changes needed)
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).send('Please provide all fields.');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO USERS (name, email, password_hash) VALUES (?, ?, ?);`;
        await dbPool.execute(sql, [name, email, hashedPassword]);
        res.send('<h1>Registration successful!</h1><p>You can now <a href="/login">log in</a>.</p>');
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send('An account with this email already exists.');
        }
        console.error("Registration Error:", error);
        res.status(500).send('An error occurred during registration.');
    }
});

// ⭐️ Changed: POST /login now creates a JWT and sets it in a cookie
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Please provide both email and password.');
    }
    try {
        const [rows] = await dbPool.execute('SELECT * FROM USERS WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).send('Invalid email or password.');
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // Passwords match! Create a JWT payload.
            const payload = {
                id: user.user_id,
                name: user.name,
                email: user.email
            };

            // Sign the token with the secret key, setting it to expire in 1 hour
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            // Send the token in a secure, http-only cookie
            res.cookie('token', token, {
                httpOnly: true,
                secure: false, // Set to true in production (HTTPS)
                maxAge: 3600000 // 1 hour in milliseconds
            });

            res.redirect('/dashboard');
        } else {
            res.status(401).send('Invalid email or password.');
        }
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).send('An error occurred during login.');
    }
});

// ⭐️ Changed: Dashboard is now a protected route using our middleware
app.get('/dashboard', authenticateToken, (req, res) => {
    // The user's data is available from the middleware via `req.user`
    res.send(`<h1>Welcome, ${req.user.name}!</h1><a href="/logout">Logout</a>`);
});

// ⭐️ Changed: Logout now clears the token cookie
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

// ### 4. Start Server ###
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
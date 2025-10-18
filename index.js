const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');         // ⭐️ New
const cookieParser = require('cookie-parser'); // ⭐️ New
require('dotenv').config();

const app = express();
const port = 3000;
app.set('view engine', 'ejs');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser()); // ⭐️ New: Use cookie parser middleware
app.use(express.static('public'));

// Create a connection pool
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ⭐️ New: Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token; // Get token from cookies

    if (!token) {
        // If no token is found, redirect to login
        return res.redirect('/login');
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user data from token to the request object
        next(); // Proceed to the protected route
    } catch (err) {
        // If token is invalid (e.g., expired), clear cookie and redirect
        res.clearCookie('token');
        return res.redirect('/login');
    }
};

// --- Page Routes ---
app.get('/', (req, res) => {
    return res.render('login');
});
app.get('/register', (req, res) => {
    return res.render('register');
});
app.get('/login', (req, res) => {
    return res.render('login');
});

// --- API Endpoints ---

// POST /register: No changes needed here
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).send('Please fill out all fields.');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Using role_id 3 as default as per earlier discussions
        const sql = `INSERT INTO USERS (name, email, password_hash, role_id) VALUES (?, ?, ?, ?);`;
        await dbPool.execute(sql, [name, email, hashedPassword, 3]);
        res.send('<h1>Registration successful!</h1><p>You can now <a href="/login">log in</a>.</p>');
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send('Error: This email is already registered.');
        }
        res.status(500).send('Error registering user.');
    }
});

// ⭐️ Changed: POST /login now creates a JWT
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Please provide both email and password.');
    }
    try {
        const sql = 'SELECT * FROM USERS WHERE email = ?';
        const [rows] = await dbPool.execute(sql, [email]);

        if (rows.length === 0) {
            return res.status(401).send('Invalid email or password.');
        }
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            // Passwords match! Create a JWT payload.
            const payload = {
                id: user.user_id,
                name: user.name,
                email: user.email,
                role_id: user.role_id
            };

            // Sign the token
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            // Send the token in a secure, http-only cookie
            res.cookie('token', token, {
                httpOnly: true, // Prevents client-side JS from accessing the cookie
                // secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
                maxAge: 3600000 // 1 hour
            });

            // Redirect to the dashboard
            res.redirect('/dashboard');
        } else {
            res.status(401).send('Invalid email or password.');
        }
    } catch (error) {
        res.status(500).send('An error occurred during login.');
    }
});

// ⭐️ Changed: GET /dashboard is now a protected route
app.get('/dashboard', authenticateToken, async (req, res) => {
    // The user's info is now available in `req.user` from the middleware
    res.render('dashboard', { user: req.user });
});

// ⭐️ New: Logout route
app.get('/logout', (req, res) => {
    res.clearCookie('token'); // Clear the cookie
    res.redirect('/login');   // Redirect to login page
});

// Start the server
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});
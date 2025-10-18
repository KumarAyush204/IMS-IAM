const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const port = 3000;
app.set('view engine', 'ejs');
//  Middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files (HTML, CSS, etc.) from the 'public' directory
app.use(express.static('public'));

// Create a connection pool for better performance
const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// --- API Endpoints ---
app.get('/',(req,res)=>{
return res.render('login')
});
app.get('/register',(req,res)=>{
return res.render('register')
});
app.get('/login',(req,res)=>{
return res.render('login')
});
// POST /register: Handle new user registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Basic validation
  if (!name || !email || !password) {
    return res.status(400).send('Please fill out all fields.');
  }

  try {
    // 🔐 Hash the password securely
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 🛡️ Use a prepared statement to prevent SQL injection
    const sql = `
      INSERT INTO USERS (name, email, password_hash, role_id) 
      VALUES (?, ?, ?, ?);
    `;
    // Assuming role_id 2 is a 'Viewer' or default user role. Make sure it exists!
    const values = [name, email, hashedPassword, 2]; 

    await dbPool.execute(sql, values);
    
    res.send('<h1>Registration successful!</h1><p>You can now <a href="/login.html">log in</a>.</p>');

  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).send('Error: This email is already registered.');
    }
    console.error(error);
    res.status(500).send('Error registering user. Please try again later.');
  }
});

// POST /login: Handle user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Please provide both email and password.');
  }

  try {
    // Find the user by email
    const sql = 'SELECT * FROM USERS WHERE email = ?';
    const [rows] = await dbPool.execute(sql, [email]);

    // Check if user exists
    if (rows.length === 0) {
      return res.status(401).send('Invalid email or password.');
    }

    const user = rows[0];

    // 🔐 Compare the provided password with the stored hash
    const match = await bcrypt.compare(password, user.password_hash);

    if (match) {
      // Passwords match!
      res.send(`<h1>Welcome, ${user.name}!</h1><p>Login successful.</p>`);
    } else {
      // Passwords do not match
      res.status(401).send('Invalid email or password.');
    }

  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred during login.');
  }
});


// Start the server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
// ### 1. Import Dependencies ###
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt =require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
require('dotenv').config();

// ### 2. App & Middleware Setup ###
const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public')); // For any static files if needed in the future

// ### 3. Database & Nodemailer Setup ###
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
console.log('✅ Database connection pool created.');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
console.log('📧 Nodemailer transporter configured.');

// ### 4. Authentication Middleware ###
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie('token');
        return res.redirect('/login');
    }
};

// --- Page Routes ---
app.get('/', (req, res) => res.redirect('/dashboard'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// --- API Endpoints ---

// POST /register
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).send('Please fill out all fields.');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await dbPool.execute(`INSERT INTO USERS (name, email, password_hash) VALUES (?, ?, ?);`, [name, email, hashedPassword]);
        res.send('<h1>Registration successful!</h1><p>You can now <a href="/login">log in</a>.</p>');
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send('Error: This email is already registered.');
        }
        console.error("Registration Error:", error);
        res.status(500).send('Error registering user.');
    }
});

// POST /login
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
            const payload = { id: user.user_id, name: user.name, email: user.email };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
            res.redirect('/dashboard');
        } else {
            res.status(401).send('Invalid email or password.');
        }
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).send('An error occurred during login.');
    }
});

// POST /organizations/create
app.post('/organizations/create', authenticateToken, async (req, res) => {
    const { org_name } = req.body;
    const owner_id = req.user.id;
    if (!org_name) {
        return res.status(400).send('Organization name is required.');
    }
    let connection;
    try {
        connection = await dbPool.getConnection();
        await connection.beginTransaction();
        const orgSql = 'INSERT INTO ORGANIZATIONS (org_name, owner_id) VALUES (?, ?)';
        const [orgResult] = await connection.execute(orgSql, [org_name, owner_id]);
        const newOrgId = orgResult.insertId;
        const ownerRoleId = 1;
        const memberSql = 'INSERT INTO ORGANIZATION_MEMBERS (org_id, user_id, role_id) VALUES (?, ?, ?)';
        await connection.execute(memberSql, [newOrgId, owner_id, ownerRoleId]);
        await connection.commit();
        res.redirect('/dashboard');
    } catch (error) {
        if (connection) await connection.rollback();
        console.error("Error creating organization:", error);
        res.status(500).send('Failed to create organization.');
    } finally {
        if (connection) connection.release();
    }
});

// POST /organizations/:orgId/add
app.post('/organizations/:orgId/add', authenticateToken, async (req, res) => {
    const { email: memberEmail } = req.body;
    const { orgId } = req.params;
    const requesterId = req.user.id; // The person trying to add a member
    const adderName = req.user.name;

    if (!memberEmail) {
        return res.status(400).send('Email is required.');
    }

    try {
        // ⭐ Step 1: Security Check - Verify the role of the user making the request.
        const requesterRoleSql = `
            SELECT r.role_name 
            FROM ORGANIZATION_MEMBERS om
            JOIN ROLES r ON om.role_id = r.role_id
            WHERE om.user_id = ? AND om.org_id = ?`;
        
        const [requesterRows] = await dbPool.execute(requesterRoleSql, [requesterId, orgId]);

        if (requesterRows.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }

        const requesterRole = requesterRows[0].role_name;
        const allowedRoles = ['Owner', 'Admin'];

        if (!allowedRoles.includes(requesterRole)) {
            return res.status(403).send("Forbidden: You do not have permission to add members to this organization.");
        }
        
        // --- If the check passes, proceed with the original logic ---

        // Step 2: Check if the user to be added is registered.
        const [users] = await dbPool.execute('SELECT user_id FROM USERS WHERE email = ?', [memberEmail]);
        if (users.length === 0) {
            return res.status(404).send('<h1>User Not Found</h1><p>A user with this email is not registered. Please ask them to create an account first.</p><a href="/dashboard">Go Back</a>');
        }
        const memberId = users[0].user_id;

        // Step 3: Check if the user is already in the organization.
        const [existingMembers] = await dbPool.execute(
            'SELECT user_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?',
            [memberId, orgId]
        );
        if (existingMembers.length > 0) {
            return res.status(409).send('<h1>Already a Member</h1><p>This user is already in the organization.</p><a href="/dashboard">Go Back</a>');
        }

        // Step 4: Add the user with the default 'Member' role (ID 3).
        await dbPool.execute(
            'INSERT INTO ORGANIZATION_MEMBERS (org_id, user_id, role_id) VALUES (?, ?, ?)',
            [orgId, memberId, 3]
        );

        // Step 5: Send a notification email.
        const [orgs] = await dbPool.execute('SELECT org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: memberEmail,
            subject: `You've been added to the organization: ${orgs[0].org_name}`,
            html: `<h1>You're on the team!</h1><p><b>${adderName}</b> has added you to the "<b>${orgs[0].org_name}</b>" organization.</p><p>You can now log in to access its resources.</p><a href="http://localhost:${PORT}/login">Login Now</a>`
        };
        await transporter.sendMail(mailOptions);

        res.redirect('/dashboard');

    } catch (error) {
        console.error("Add Member Error:", error);
        res.status(500).send('Failed to add member to the organization.');
    }
});
// GET /dashboard
app.get('/dashboard', authenticateToken, async (req, res) => {
    try {
        const sql = `
            SELECT o.org_id, o.org_name, r.role_name
            FROM ORGANIZATION_MEMBERS om
            JOIN ORGANIZATIONS o ON om.org_id = o.org_id
            JOIN ROLES r ON om.role_id = r.role_id
            WHERE om.user_id = ?`;
        const [organizations] = await dbPool.execute(sql, [req.user.id]);
        res.render('dashboard', { user: req.user, organizations: organizations });
    } catch (error) {
        console.error("Error fetching dashboard data:", error);
        res.status(500).send('Could not load dashboard data.');
    }
});

// ⭐ New: GET route to show all members of an organization
app.get('/organizations/:orgId/members', authenticateToken, async (req, res) => {
    const { orgId } = req.params;
    const userId = req.user.id;

    try {
        // Security Check: Verify the current user is a member of this organization.
        const [membershipCheck] = await dbPool.execute(
            'SELECT role_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?',
            [userId, orgId]
        );
        if (membershipCheck.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }

        // Fetch organization name
        const [orgs] = await dbPool.execute('SELECT org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        if (orgs.length === 0) return res.status(404).send("Organization not found.");
        
        // Fetch all members of this organization, including their current role_id
        const membersSql = `
            SELECT u.user_id, u.name, u.email, r.role_name, om.role_id
            FROM ORGANIZATION_MEMBERS om
            JOIN USERS u ON om.user_id = u.user_id
            JOIN ROLES r ON om.role_id = r.role_id
            WHERE om.org_id = ? ORDER BY r.role_id, u.name;
        `;
        const [members] = await dbPool.execute(membersSql, [orgId]);

        // Fetch all possible roles for the 'organization' scope to populate the dropdown
        const [orgRoles] = await dbPool.execute(
            `SELECT role_id, role_name FROM ROLES WHERE scope = 'organization'`
        );

        res.render('org-members', {
            user: req.user,
            orgName: orgs[0].org_name,
            orgId: orgId,
            members: members,
            orgRoles: orgRoles // Pass the roles to the view
        });

    } catch (error) {
        console.error("Error fetching organization members:", error);
        res.status(500).send("Failed to retrieve organization members.");
    }
});

// ⭐ New: POST route to handle updating a user's role
app.post('/organizations/:orgId/members/:memberId/update-role', authenticateToken, async (req, res) => {
    const { orgId, memberId } = req.params;
    const { new_role_id } = req.body;
    const requesterId = req.user.id;

    try {
        // Security Check 1: Get the role of the person MAKING the request
        const [requesterRows] = await dbPool.execute(
            'SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?',
            [requesterId, orgId]
        );

        if (requesterRows.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }
        
        const requesterRole = requesterRows[0].role_name;
        const allowedRoles = ['Owner', 'Admin'];

        // Security Check 2: Ensure the requester is an Owner or Admin
        if (!allowedRoles.includes(requesterRole)) {
            return res.status(403).send("Forbidden: You do not have permission to change roles.");
        }
        
        // Security Check 3: Prevent the Owner's role from being changed by anyone
        const [targetUserRows] = await dbPool.execute(
            'SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?',
            [memberId, orgId]
        );

        if (targetUserRows.length > 0 && targetUserRows[0].role_name === 'Owner') {
            return res.status(403).send("Forbidden: The role of the organization owner cannot be changed.");
        }

        // All checks passed, update the user's role in the database
        const updateSql = 'UPDATE ORGANIZATION_MEMBERS SET role_id = ? WHERE user_id = ? AND org_id = ?';
        await dbPool.execute(updateSql, [new_role_id, memberId, orgId]);

        // Redirect back to the members page
        res.redirect(`/organizations/${orgId}/members`);
        
    } catch (error) {
        console.error("Error updating user role:", error);
        res.status(500).send("Failed to update user role.");
    }
});
// GET /logout
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

// ### 5. Start Server ###
app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
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


app.get('/organizations/:orgId', authenticateToken, async (req, res) => {
    const { orgId } = req.params;
    const userId = req.user.id;

    try {
        // Security: Ensure the user is a member of the org they are trying to view
        const [membership] = await dbPool.execute(
            'SELECT org_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?',
            [userId, orgId]
        );
        if (membership.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }

        // Fetch organization details
        const [orgs] = await dbPool.execute('SELECT org_id, org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        if (orgs.length === 0) {
            return res.status(404).send("Organization not found.");
        }

        res.render('org-management', { user: req.user, org: orgs[0] });

    } catch (error) {
        console.error("Error fetching organization page:", error);
        res.status(500).send("Failed to load organization page.");
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



// ⭐ New: POST route to handle team creation within an organization
app.post('/organizations/:orgId/teams/create', authenticateToken, async (req, res) => {
    const { orgId } = req.params;
    const { team_name } = req.body;
    const requesterId = req.user.id;

    if (!team_name) {
        return res.status(400).send("Team name is required.");
    }

    try {
        // Security Check: Verify the user is an Owner or Admin of this organization.
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
            return res.status(403).send("Forbidden: You do not have permission to create teams.");
        }

        // All checks passed, create the team.
        const createTeamSql = 'INSERT INTO TEAMS (team_name, org_id) VALUES (?, ?)';
        await dbPool.execute(createTeamSql, [team_name, orgId]);

        // Redirect back to the members management page.
        res.redirect(`/organizations/${orgId}/members`);

    } catch (error) {
        console.error("Error creating team:", error);
        res.status(500).send("Failed to create team.");
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
// ⭐ Corrected: This route now correctly fetches the user_id for team members.
app.get('/organizations/:orgId/members', authenticateToken, async (req, res) => {
    const { orgId } = req.params;
    const userId = req.user.id;

    try {
        // Step 1: Security Check - Verify the user is a member of the organization.
        const [membershipCheck] = await dbPool.execute(
            'SELECT role_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?',
            [userId, orgId]
        );
        if (membershipCheck.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }

        // Step 2: Fetch all primary data in parallel for efficiency.
        // Get organization details.
        const [orgs] = await dbPool.execute('SELECT org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        if (orgs.length === 0) {
            return res.status(404).send("Organization not found.");
        }
        
        // Get all members of the organization.
        const membersSql = `
            SELECT u.user_id, u.name, u.email, r.role_name, om.role_id 
            FROM ORGANIZATION_MEMBERS om 
            JOIN USERS u ON om.user_id = u.user_id 
            JOIN ROLES r ON om.role_id = r.role_id 
            WHERE om.org_id = ? ORDER BY r.role_id, u.name;`;
        const [members] = await dbPool.execute(membersSql, [orgId]);
        
        // Get all possible roles for the 'organization' scope.
        const [orgRoles] = await dbPool.execute(`SELECT role_id, role_name FROM ROLES WHERE scope = 'organization'`);
        
        // Get all teams within the organization.
        const [teams] = await dbPool.execute('SELECT team_id, team_name FROM TEAMS WHERE org_id = ?', [orgId]);
        
        // Get all possible roles for the 'team' scope.
        const [teamRoles] = await dbPool.execute(`SELECT role_id, role_name FROM ROLES WHERE scope = 'team'`);

        // Step 3: Fetch members for each team and structure the data.
        const teamsWithMembers = await Promise.all(teams.map(async (team) => {
            const teamMembersSql = `
                SELECT u.user_id, u.name, r.role_id, r.role_name
                FROM TEAM_MEMBERS tm 
                JOIN USERS u ON tm.user_id = u.user_id
                JOIN ROLES r ON tm.role_id = r.role_id
                WHERE tm.team_id = ?`;
            const [teamMembers] = await dbPool.execute(teamMembersSql, [team.team_id]);
            
            // Return a new object for the team that includes its members list.
            return {
                ...team,
                members: teamMembers
            };
        }));

        // Step 4: Render the page with all the fetched and structured data.
        res.render('org-members', {
            user: req.user,
            orgName: orgs[0].org_name,
            orgId: orgId,
            members: members,       // List of organization members
            orgRoles: orgRoles,     // List of possible organization roles
            teams: teamsWithMembers,// List of teams, each with its members
            teamRoles: teamRoles    // List of possible team roles
        });

    } catch (error) {
        console.error("Error fetching organization members:", error);
        res.status(500).send("Failed to retrieve organization members.");
    }
});
app.post('/teams/:teamId/members/:memberId/remove', authenticateToken, async (req, res) => {
    const { teamId, memberId } = req.params;
    const { orgId } = req.body; // Pass orgId in a hidden field for redirection
    const requesterId = req.user.id;

    if (!orgId) {
        return res.status(400).send("Organization ID is missing.");
    }

    try {
        // Security Check: Verify the user making the request is an Owner or Admin of the organization.
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
            return res.status(403).send("Forbidden: You do not have permission to remove team members.");
        }

        // All checks passed. Delete the user from the TEAM_MEMBERS table.
        const deleteSql = 'DELETE FROM TEAM_MEMBERS WHERE team_id = ? AND user_id = ?';
        await dbPool.execute(deleteSql, [teamId, memberId]);

        // Redirect back to the members management page.
        res.redirect(`/organizations/${orgId}/members`);

    } catch (error) {
        console.error("Error removing member from team:", error);
        res.status(500).send("Failed to remove member from team.");
    }
});

// ⭐ New: POST route to handle updating a user's role
app.post('/organizations/:orgId/members/:memberId/update-role', authenticateToken, async (req, res) => {
    const { orgId, memberId } = req.params;
    const { new_role_id } = req.body;
    const requesterId = req.user.id;

    try {
        // 🛡️ Security Check: Get the role of the person MAKING the request
        const [requesterRows] = await dbPool.execute(
            'SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?',
            [requesterId, orgId]
        );

        // Debugging log
        console.log(`SECURITY CHECK (Org Role Update): User ${requesterId} attempting action on org ${orgId}.`);

        if (requesterRows.length === 0) {
            console.log(`-> DENIED: Requester is not a member of this organization.`);
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }
        
        const requesterRole = requesterRows[0].role_name;
        const allowedRoles = ['Owner', 'Admin'];

        console.log(`-> Requester's role is '${requesterRole}'. Allowed roles: ['Owner', 'Admin'].`);

        // Security Check: Ensure the requester is an Owner or Admin
        if (!allowedRoles.includes(requesterRole)) {
            console.log(`-> DENIED: Role '${requesterRole}' is not authorized.`);
            return res.status(403).send("Forbidden: You do not have permission to change roles.");
        }
        
        console.log(`-> ALLOWED: Proceeding with role update.`);

        // Security Check: Prevent the Owner's role from being changed
        const [targetUserRows] = await dbPool.execute('SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?', [memberId, orgId]);
        if (targetUserRows.length > 0 && targetUserRows[0].role_name === 'Owner') {
            return res.status(403).send("Forbidden: The role of the organization owner cannot be changed.");
        }

        // All checks passed, update the user's role
        const updateSql = 'UPDATE ORGANIZATION_MEMBERS SET role_id = ? WHERE user_id = ? AND org_id = ?';
        await dbPool.execute(updateSql, [new_role_id, memberId, orgId]);

        res.redirect(`/organizations/${orgId}/members`);
        
    } catch (error) {
        console.error("Error updating user role:", error);
        res.status(500).send("Failed to update user role.");
    }
});


// ⭐ New: POST route to handle organization deletion
app.post('/organizations/:orgId/delete', authenticateToken, async (req, res) => {
    const { orgId } = req.params;
    const { confirmation_name } = req.body;
    const requesterId = req.user.id;

    try {
        // 🛡️ Security Check 1: Verify the requester is the OWNER of this organization.
        const roleSql = `
            SELECT r.role_name FROM ORGANIZATION_MEMBERS om
            JOIN ROLES r ON om.role_id = r.role_id
            WHERE om.user_id = ? AND om.org_id = ?`;
        
        const [requesterRows] = await dbPool.execute(roleSql, [requesterId, orgId]);

        if (requesterRows.length === 0 || requesterRows[0].role_name !== 'Owner') {
            return res.status(403).send("Forbidden: Only the organization owner can delete the organization.");
        }

        // 🛡️ Security Check 2: Verify the typed confirmation name matches the actual name.
        const [orgs] = await dbPool.execute('SELECT org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        if (orgs.length === 0) {
            return res.status(404).send("Organization not found.");
        }

        if (orgs[0].org_name !== confirmation_name) {
            return res.status(400).send("Confirmation name does not match. Deletion aborted.");
        }

        // 🗑️ All checks passed. Proceed with deletion.
        // Because of `ON DELETE CASCADE` in your database schema, deleting the organization
        // will automatically delete all related teams, members, inventories, etc.
        await dbPool.execute('DELETE FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);

        // Redirect to the dashboard after successful deletion.
        res.redirect('/dashboard');

    } catch (error) {
        console.error("Error deleting organization:", error);
        res.status(500).send("Failed to delete organization.");
    }
});


// ⭐ New: POST route to assign an organization member to a team
app.post('/organizations/:orgId/members/:memberId/assign-team', authenticateToken, async (req, res) => {
    const { orgId, memberId } = req.params;
    const { team_id } = req.body;
    const requesterId = req.user.id;

    if (!team_id) {
        return res.status(400).send("Team ID is required.");
    }

    try {
        // Security Check: Verify the user making the request is an Owner or Admin.
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
            return res.status(403).send("Forbidden: You do not have permission to assign members to teams.");
        }

        // Check if the user is already in the team to prevent duplicate entries.
        const [existing] = await dbPool.execute(
            'SELECT * FROM TEAM_MEMBERS WHERE user_id = ? AND team_id = ?',
            [memberId, team_id]
        );
        if (existing.length > 0) {
            // Optionally, you can send a message back. For now, we just redirect.
            return res.redirect(`/organizations/${orgId}/members`);
        }

        // All checks passed. Add the user to the team with the default 'Team Member' role (ID 5).
        const assignSql = 'INSERT INTO TEAM_MEMBERS (team_id, user_id, role_id) VALUES (?, ?, ?)';
        await dbPool.execute(assignSql, [team_id, memberId, 5]);

        // Redirect back to the members management page.
        res.redirect(`/organizations/${orgId}/members`);

    } catch (error) {
        console.error("Error assigning member to team:", error);
        res.status(500).send("Failed to assign member to team.");
    }
});
// ⭐ New: POST route to update a team member's role
app.post('/teams/:teamId/members/:memberId/update-role', authenticateToken, async (req, res) => {
    const { teamId, memberId } = req.params;
    const { new_team_role_id, orgId } = req.body;
    const requesterId = req.user.id;

    if (!new_team_role_id || !orgId) {
        return res.status(400).send("Missing required information.");
    }

    try {
        // 🛡️ Security Check: Get the requester's organization-level role
        const [orgRoleRows] = await dbPool.execute(`SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?`, [requesterId, orgId]);

        console.log(`SECURITY CHECK (Team Role Update): User ${requesterId} attempting action on team ${teamId}.`);

        if (orgRoleRows.length === 0) {
            console.log(`-> DENIED: Requester is not a member of this organization.`);
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }

        const orgRole = orgRoleRows[0].role_name;
        const allowedOrgRoles = ['Owner', 'Admin'];

        console.log(`-> Requester's organization role is '${orgRole}'.`);

        // If the requester is an Owner or Admin of the organization, they are allowed
        if (allowedOrgRoles.includes(orgRole)) {
            console.log(`-> ALLOWED (as Org Admin/Owner): Proceeding with role update.`);
        } else {
            // Otherwise, check if they are a Team Admin for this specific team
            const [teamRoleRows] = await dbPool.execute(`SELECT r.role_name FROM TEAM_MEMBERS tm JOIN ROLES r ON tm.role_id = r.role_id WHERE tm.user_id = ? AND tm.team_id = ?`, [requesterId, teamId]);
            const teamRole = teamRoleRows.length > 0 ? teamRoleRows[0].role_name : null;
            
            console.log(`-> Requester's team role is '${teamRole}'.`);

            if (teamRole !== 'Team Admin') {
                console.log(`-> DENIED: Not an Org Admin/Owner or a Team Admin.`);
                return res.status(403).send("Forbidden: You do not have permission to change roles in this team.");
            }
            console.log(`-> ALLOWED (as Team Admin): Proceeding with role update.`);
        }

        // All security checks passed, update the role
        const updateSql = 'UPDATE TEAM_MEMBERS SET role_id = ? WHERE team_id = ? AND user_id = ?';
        await dbPool.execute(updateSql, [new_team_role_id, teamId, memberId]);

        res.redirect(`/organizations/${orgId}/members`);

    } catch (error) {
        console.error("Error updating team role:", error);
        res.status(500).send("Failed to update team member role.");
    }
});
app.get('/teams/:teamId', authenticateToken, async (req, res) => {
    const { teamId } = req.params;
    const requesterId = req.user.id;

    try {
        // ⭐ FIX: Added 'team_id' to the SELECT statement
        const [teams] = await dbPool.execute('SELECT team_id, team_name, org_id FROM TEAMS WHERE team_id = ?', [teamId]);
        if (teams.length === 0) {
            return res.status(404).send("Team not found.");
        }
        const team = teams[0];

        // Security Check: Verify the user is a member of this team's organization
        const [orgMembership] = await dbPool.execute('SELECT role_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?', [requesterId, team.org_id]);
        if (orgMembership.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this team's organization.");
        }
        
        // Fetch inventories assigned to this specific team
        const inventoriesSql = `
            SELECT i.inventory_name 
            FROM INVENTORY_ASSIGNMENTS ia 
            JOIN INVENTORIES i ON ia.inventory_id = i.inventory_id 
            WHERE ia.team_id = ?`;
        const [inventories] = await dbPool.execute(inventoriesSql, [teamId]);

        // Permission Check for displaying the create form
        const [orgRoleRows] = await dbPool.execute(`SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?`, [requesterId, team.org_id]);
        const [teamRoleRows] = await dbPool.execute(`SELECT r.role_name FROM TEAM_MEMBERS tm JOIN ROLES r ON tm.role_id = r.role_id WHERE tm.user_id = ? AND tm.team_id = ?`, [requesterId, teamId]);
        
        const orgRole = orgRoleRows.length > 0 ? orgRoleRows[0].role_name : null;
        const teamRole = teamRoleRows.length > 0 ? teamRoleRows[0].role_name : null;
        const userIsAdmin = (orgRole === 'Owner' || orgRole === 'Admin' || teamRole === 'Team Admin');

        res.render('team-management', {
            user: req.user,
            team: team, // This 'team' object now correctly contains the team_id
            orgId: team.org_id,
            inventories: inventories,
            userIsAdmin: userIsAdmin
        });

    } catch (error) {
        console.error("Error fetching team management page:", error);
        res.status(500).send("Failed to load page.");
    }
});

// ⭐ New: POST route to handle inventory creation for a team
app.post('/teams/:teamId/inventories/create', authenticateToken, async (req, res) => {
    const { teamId } = req.params;
    const { inventory_name, orgId } = req.body;
    const requesterId = req.user.id;

    if (!inventory_name || !orgId) {
        return res.status(400).send("Missing required information.");
    }

    let connection;
    try {
        // Security Check (same as above): Verify user is an Org Owner/Admin or Team Admin
        const [orgRoleRows] = await dbPool.execute(`SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?`, [requesterId, orgId]);
        const [teamRoleRows] = await dbPool.execute(`SELECT r.role_name FROM TEAM_MEMBERS tm JOIN ROLES r ON tm.role_id = r.role_id WHERE tm.user_id = ? AND tm.team_id = ?`, [requesterId, teamId]);
        const orgRole = orgRoleRows.length > 0 ? orgRoleRows[0].role_name : null;
        const teamRole = teamRoleRows.length > 0 ? teamRoleRows[0].role_name : null;

        if (orgRole !== 'Owner' && orgRole !== 'Admin' && teamRole !== 'Team Admin') {
            return res.status(403).send("Forbidden: You do not have permission to create inventories.");
        }

        // Use a transaction for data integrity
        connection = await dbPool.getConnection();
        await connection.beginTransaction();

        // 1. Create the inventory at the organization level
        const inventorySql = 'INSERT INTO INVENTORIES (inventory_name, org_id) VALUES (?, ?)';
        const [invResult] = await connection.execute(inventorySql, [inventory_name, orgId]);
        const newInventoryId = invResult.insertId;

        // 2. Assign the new inventory to this specific team
        const assignmentSql = 'INSERT INTO INVENTORY_ASSIGNMENTS (inventory_id, team_id) VALUES (?, ?)';
        await connection.execute(assignmentSql, [newInventoryId, teamId]);

        await connection.commit();
        res.redirect(`/teams/${teamId}`);

    } catch (error) {
        if (connection) await connection.rollback();
        console.error("Error creating inventory:", error);
        res.status(500).send("Failed to create inventory.");
    } finally {
        if (connection) connection.release();
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
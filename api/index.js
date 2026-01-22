
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt =require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const path=require('path');
require('dotenv').config();
const serverless = require('serverless-http');

const app = express();
const PORT = process.env.APP_PORT || 3002;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

//For Local Setup
// const dbPool = mysql.createPool({
//     host: process.env.DB_HOST,
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_NAME
// });


const dbPool = mysql.createPool({
    host: process.env.TIDB_HOST,
    port: process.env.TIDB_PORT || 4000,
    user: process.env.TIDB_USER,
    password: process.env.TIDB_PASSWORD,
    database: process.env.TIDB_DATABASE,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    waitForConnections: true,
    connectionLimit: 1, // Recommended for Serverless to avoid exhausting connections
    maxIdle: 1,
    idleTimeout: 60000,
    queueLimit: 0,
});
console.log('Database connection created.');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
console.log('Nodemailer configured.');

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

app.get('/', (req, res) => res.redirect('/dashboard'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));


app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).send('Please fill out all fields.');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await dbPool.execute(`INSERT INTO USERS (name, email, password_hash) VALUES (?, ?, ?);`, [name, email, hashedPassword]);
        res.send(`
  <div style="font-family: sans-serif; text-align: center; padding-top: 100px; color: #333;">
    <h1 style="color: #28a745;">Registration successful!</h1>
    <p>You can now <a href="/login" style="color: #007bff; text-decoration: none; font-weight: bold;">log in</a>.</p>
  </div>
`);
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send('Error: This email is already registered.');
        }
        console.error("Registration Error:", error);
        res.status(500).send('Error registering user.');
    }
});

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
        
        const [membership] = await dbPool.execute(
            'SELECT org_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?',
            [userId, orgId]
        );
        if (membership.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }

        const [orgs] = await dbPool.execute('SELECT org_id, org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        if (orgs.length === 0) {
            return res.status(404).send("Organization not found.");
        }

        res.render('org-members', { user: req.user, org: orgs[0] });

    } catch (error) {
        console.error("Error fetching organization page:", error);
        res.status(500).send("Failed to load organization page.");
    }
});

app.post('/organizations/:orgId/add', authenticateToken, async (req, res) => {
    const { email: memberEmail } = req.body;
    const { orgId } = req.params;
    const requesterId = req.user.id; 
    const adderName = req.user.name;

    if (!memberEmail) {
        return res.status(400).send('Email is required.');
    }

    try {

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
        
        
        const [users] = await dbPool.execute('SELECT user_id FROM USERS WHERE email = ?', [memberEmail]);
        if (users.length === 0) {
            return res.status(404).send('<h1>User Not Found</h1><p>A user with this email is not registered. Please ask them to create an account first.</p><a href="/dashboard">Go Back</a>');
        }
        const memberId = users[0].user_id;

        
        const [existingMembers] = await dbPool.execute(
            'SELECT user_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?',
            [memberId, orgId]
        );
        if (existingMembers.length > 0) {
            return res.status(409).send('<h1>Already a Member</h1><p>This user is already in the organization.</p><a href="/dashboard">Go Back</a>');
        }

        
        await dbPool.execute(
            'INSERT INTO ORGANIZATION_MEMBERS (org_id, user_id, role_id) VALUES (?, ?, ?)',
            [orgId, memberId, 3]
        );

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



app.post('/organizations/:orgId/teams/create', authenticateToken, async (req, res) => {
    const { orgId } = req.params;
    const { team_name } = req.body;
    const requesterId = req.user.id;

    if (!team_name) {
        return res.status(400).send("Team name is required.");
    }

    try {
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

        const createTeamSql = 'INSERT INTO TEAMS (team_name, org_id) VALUES (?, ?)';
        await dbPool.execute(createTeamSql, [team_name, orgId]);

        res.redirect(`/organizations/${orgId}/members`);

    } catch (error) {
        console.error("Error creating team:", error);
        res.status(500).send("Failed to create team.");
    }
});







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

app.get('/organizations/:orgId/members', authenticateToken, async (req, res) => {
    const { orgId } = req.params;
    const userId = req.user.id;

    try {
        const [membershipCheck] = await dbPool.execute(
            'SELECT role_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?',
            [userId, orgId]
        );
        if (membershipCheck.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }

        const [orgs] = await dbPool.execute('SELECT org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        if (orgs.length === 0) {
            return res.status(404).send("Organization not found.");
        }
        
        const membersSql = `
            SELECT u.user_id, u.name, u.email, r.role_name, om.role_id 
            FROM ORGANIZATION_MEMBERS om 
            JOIN USERS u ON om.user_id = u.user_id 
            JOIN ROLES r ON om.role_id = r.role_id 
            WHERE om.org_id = ? ORDER BY r.role_id, u.name;`;
        const [members] = await dbPool.execute(membersSql, [orgId]);
      
        const [orgRoles] = await dbPool.execute(`SELECT role_id, role_name FROM ROLES WHERE scope = 'organization'`);
        
        const [teams] = await dbPool.execute('SELECT team_id, team_name FROM TEAMS WHERE org_id = ?', [orgId]);
        
        const [teamRoles] = await dbPool.execute(`SELECT role_id, role_name FROM ROLES WHERE scope = 'team'`);


        const teamsWithMembers = await Promise.all(teams.map(async (team) => {
            const teamMembersSql = `
                SELECT u.user_id, u.name, r.role_id, r.role_name
                FROM TEAM_MEMBERS tm 
                JOIN USERS u ON tm.user_id = u.user_id
                JOIN ROLES r ON tm.role_id = r.role_id
                WHERE tm.team_id = ?`;
            const [teamMembers] = await dbPool.execute(teamMembersSql, [team.team_id]);
            
            return {
                ...team,
                members: teamMembers
            };
        }));

        res.render('org-members', {
            user: req.user,
            orgName: orgs[0].org_name,
            orgId: orgId,
            members: members,      
            orgRoles: orgRoles,     
            teams: teamsWithMembers,
            teamRoles: teamRoles    
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


        const deleteSql = 'DELETE FROM TEAM_MEMBERS WHERE team_id = ? AND user_id = ?';
        await dbPool.execute(deleteSql, [teamId, memberId]);

        res.redirect(`/organizations/${orgId}/members`);

    } catch (error) {
        console.error("Error removing member from team:", error);
        res.status(500).send("Failed to remove member from team.");
    }
});

app.post('/organizations/:orgId/members/:memberId/update-role', authenticateToken, async (req, res) => {
    const { orgId, memberId } = req.params;
    const { new_role_id } = req.body;
    const requesterId = req.user.id;

    try {
        const [requesterRows] = await dbPool.execute(
            'SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?',
            [requesterId, orgId]
        );

        console.log(`SECURITY CHECK (Org Role Update): User ${requesterId} attempting action on org ${orgId}.`);

        if (requesterRows.length === 0) {
            console.log(`-> DENIED: Requester is not a member of this organization.`);
            return res.status(403).send("Forbidden: You are not a member of this organization.");
        }
        
        const requesterRole = requesterRows[0].role_name;
        const allowedRoles = ['Owner', 'Admin'];

        console.log(`-> Requester's role is '${requesterRole}'. Allowed roles: ['Owner', 'Admin'].`);


        if (!allowedRoles.includes(requesterRole)) {
            console.log(`-> DENIED: Role '${requesterRole}' is not authorized.`);
            return res.status(403).send("Forbidden: You do not have permission to change roles.");
        }
        
        console.log(`-> ALLOWED: Proceeding with role update.`);

        const [targetUserRows] = await dbPool.execute('SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?', [memberId, orgId]);
        if (targetUserRows.length > 0 && targetUserRows[0].role_name === 'Owner') {
            return res.status(403).send("Forbidden: The role of the organization owner cannot be changed.");
        }

        const updateSql = 'UPDATE ORGANIZATION_MEMBERS SET role_id = ? WHERE user_id = ? AND org_id = ?';
        await dbPool.execute(updateSql, [new_role_id, memberId, orgId]);

        res.redirect(`/organizations/${orgId}/members`);
        
    } catch (error) {
        console.error("Error updating user role:", error);
        res.status(500).send("Failed to update user role.");
    }
});


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

        const [orgs] = await dbPool.execute('SELECT org_name FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);
        if (orgs.length === 0) {
            return res.status(404).send("Organization not found.");
        }

        if (orgs[0].org_name !== confirmation_name) {
            return res.status(400).send("Confirmation name does not match. Deletion aborted.");
        }


        await dbPool.execute('DELETE FROM ORGANIZATIONS WHERE org_id = ?', [orgId]);

        res.redirect('/dashboard');

    } catch (error) {
        console.error("Error deleting organization:", error);
        res.status(500).send("Failed to delete organization.");
    }
});


app.post('/organizations/:orgId/members/:memberId/assign-team', authenticateToken, async (req, res) => {
    const { orgId, memberId } = req.params;
    const { team_id } = req.body;
    const requesterId = req.user.id;

    if (!team_id) {
        return res.status(400).send("Team ID is required.");
    }

    try {
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

        const [existing] = await dbPool.execute(
            'SELECT * FROM TEAM_MEMBERS WHERE user_id = ? AND team_id = ?',
            [memberId, team_id]
        );
        if (existing.length > 0) {
            
            return res.redirect(`/organizations/${orgId}/members`);
        }

        const assignSql = 'INSERT INTO TEAM_MEMBERS (team_id, user_id, role_id) VALUES (?, ?, ?)';
        await dbPool.execute(assignSql, [team_id, memberId, 5]);

        res.redirect(`/organizations/${orgId}/members`);

    } catch (error) {
        console.error("Error assigning member to team:", error);
        res.status(500).send("Failed to assign member to team.");
    }
});
app.post('/teams/:teamId/members/:memberId/update-role', authenticateToken, async (req, res) => {
    const { teamId, memberId } = req.params;
    const { new_team_role_id, orgId } = req.body;
    const requesterId = req.user.id;

    if (!new_team_role_id || !orgId) {
        return res.status(400).send("Missing required information.");
    }

    try {
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
        const [teams] = await dbPool.execute(
            'SELECT team_id, team_name, org_id FROM TEAMS WHERE team_id = ?', 
            [teamId]
        );
        if (teams.length === 0) {
            return res.status(404).send("Team not found.");
        }
        const team = teams[0];

        const [orgMembership] = await dbPool.execute(
            'SELECT role_id FROM ORGANIZATION_MEMBERS WHERE user_id = ? AND org_id = ?', 
            [requesterId, team.org_id]
        );
        if (orgMembership.length === 0) {
            return res.status(403).send("Forbidden: You are not a member of this team's organization.");
        }
        
        const inventoriesSql = `
            SELECT i.inventory_id, i.inventory_name 
            FROM INVENTORY_ASSIGNMENTS ia 
            JOIN INVENTORIES i ON ia.inventory_id = i.inventory_id 
            WHERE ia.team_id = ?`;
        const [inventories] = await dbPool.execute(inventoriesSql, [teamId]);

      
        const [orgRoleRows] = await dbPool.execute(`SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?`, [requesterId, team.org_id]);
        const [teamRoleRows] = await dbPool.execute(`SELECT r.role_name FROM TEAM_MEMBERS tm JOIN ROLES r ON tm.role_id = r.role_id WHERE tm.user_id = ? AND tm.team_id = ?`, [requesterId, teamId]);
        
        const orgRole = orgRoleRows.length > 0 ? orgRoleRows[0].role_name : null;
        const teamRole = teamRoleRows.length > 0 ? teamRoleRows[0].role_name : null;
        
        const userIsAdmin = (orgRole === 'Owner' || orgRole === 'Admin' || teamRole === 'Team Admin');


        res.render('team-management', {
            user: req.user,
            team: team, 
            orgId: team.org_id,
            inventories: inventories,
            userIsAdmin: userIsAdmin
        });

    } catch (error) {
        console.error("Error fetching team management page:", error);
        res.status(500).send("Failed to load page.");
    }
});

app.post('/inventories/:inventoryId/items/create', authenticateToken, async (req, res) => {
    const { inventoryId } = req.params;
    const { item_name, quantity, threshold, teamId } = req.body;
    const requesterId = req.user.id;

    const securitySql = `SELECT ia.team_id FROM INVENTORY_ASSIGNMENTS ia JOIN TEAM_MEMBERS tm ON ia.team_id = tm.team_id WHERE ia.inventory_id = ? AND tm.user_id = ? AND ia.team_id = ?`;
    const [permission] = await dbPool.execute(securitySql, [inventoryId, requesterId, teamId]);
    if (permission.length === 0) return res.status(403).send("Forbidden...");

    let connection;
    try {
        connection = await dbPool.getConnection();
        await connection.beginTransaction();

        // 1. Insert the new item
        const itemSql = 'INSERT INTO INVENTORY_ITEMS (inventory_id, item_name, quantity, threshold) VALUES (?, ?, ?, ?)';
        const [itemResult] = await connection.execute(itemSql, [inventoryId, item_name, quantity, threshold]);
        const newItemId = itemResult.insertId;

        const logSql = 'INSERT INTO MOVEMENT_LOGS (item_id, user_id, action, quantity_change, notes) VALUES (?, ?, ?, ?, ?)';
        await connection.execute(logSql, [newItemId, requesterId, 'add', quantity, 'Item created']);

        await connection.commit();
        res.redirect(`/inventories/${inventoryId}?teamId=${teamId}`);
    } catch (error) {
        if (connection) await connection.rollback();
        console.error("Error creating item:", error);
        res.status(500).send("Failed to create item.");
    } finally {
        if (connection) connection.release();
    }
});


app.post('/items/:itemId/update-stock', authenticateToken, async (req, res) => {
    const { itemId } = req.params;
    const { quantity_change, action, inventoryId, teamId } = req.body;
    const requesterId = req.user.id;
    const requesterName = req.user.name;

    if (!inventoryId || !teamId || !quantity_change || !action) {
        return res.status(400).send("Missing required information.");
    }
    const change = parseInt(quantity_change, 10);
    if (isNaN(change) || change <= 0) {
        return res.status(400).send("Invalid quantity change.");
    }

    let connection;
    try {
        const [invOrg] = await dbPool.execute('SELECT org_id FROM INVENTORIES WHERE inventory_id = ?', [inventoryId]);
        if (invOrg.length === 0) return res.status(404).send("Inventory not found.");
        const orgId = invOrg[0].org_id;
        const secureCheckSql = `SELECT tm.user_id FROM TEAM_MEMBERS tm JOIN INVENTORY_ASSIGNMENTS ia ON tm.team_id = ia.team_id WHERE tm.user_id = ? AND ia.inventory_id = ? AND tm.team_id = ?`;
        const [permissionRows] = await dbPool.execute(secureCheckSql, [requesterId, inventoryId, teamId]);
        if (permissionRows.length === 0) return res.status(403).send("Forbidden...");
      

        connection = await dbPool.getConnection();
        await connection.beginTransaction();


        const [currentItemStateRows] = await connection.execute(
            'SELECT quantity, threshold FROM INVENTORY_ITEMS WHERE item_id = ?',
            [itemId]
        );
        if (currentItemStateRows.length === 0) {
            await connection.rollback();
            return res.status(404).send("Item not found.");
        }
        const originalQuantity = currentItemStateRows[0].quantity;
        const threshold = currentItemStateRows[0].threshold;

        // 2. Update the quantity
        const operator = action === 'add' ? '+' : '-';
        const updateSql = `UPDATE INVENTORY_ITEMS SET quantity = quantity ${operator} ? WHERE item_id = ?`;
        const [updateResult] = await connection.execute(updateSql, [change, itemId]);

        // Check update success
        if (updateResult.affectedRows === 0) {
            await connection.rollback();
            return res.status(404).send("Item not found or stock update failed.");
        }

        // 3. Get the NEW quantity AFTER update
        const [newItemStateRows] = await connection.execute(
            'SELECT quantity FROM INVENTORY_ITEMS WHERE item_id = ?',
            [itemId]
        );
        const newQuantity = newItemStateRows[0].quantity;

        // Check for negative stock
        if (newQuantity < 0) {
            await connection.rollback();
            return res.status(400).send("Stock cannot go below zero.");
        }

        // 4. Log the movement
        const finalChange = action === 'add' ? change : -change;
        const logSql = 'INSERT INTO MOVEMENT_LOGS (item_id, user_id, action, quantity_change) VALUES (?, ?, ?, ?)';
        await connection.execute(logSql, [itemId, requesterId, action, finalChange]);

        // 5. Commit the transaction
        await connection.commit();
        connection.release(); // Release connection

        
        try {
            // Get item name and inventory name for emails
            const itemDetailsSql = `
                SELECT i.item_name, inv.inventory_name, inv.org_id
                FROM INVENTORY_ITEMS i
                JOIN INVENTORIES inv ON i.inventory_id = inv.inventory_id
                WHERE i.item_id = ?`;
            const [itemDetailsRows] = await dbPool.execute(itemDetailsSql, [itemId]);
            const item = itemDetailsRows[0];

            // Find Admins/Owner
            const adminEmailsSql = `
                SELECT u.email FROM ORGANIZATION_MEMBERS om
                JOIN USERS u ON om.user_id = u.user_id
                WHERE om.org_id = ? AND om.role_id IN (1, 2)`; // 1=Owner, 2=Admin
            const [adminRows] = await dbPool.execute(adminEmailsSql, [item.org_id]);
            const adminEmails = adminRows.map(row => row.email);

            if (adminEmails.length > 0) {
                // Condition 1: Check for Low Stock
                if (newQuantity <= threshold) {
                    console.log(`Threshold breached for item "${item.item_name}". Notifying admins...`);
                    const mailOptions = {
                        from: process.env.EMAIL_USER,
                        to: adminEmails.join(', '),
                        subject: `Low Stock Alert: ${item.item_name}`,
                        html: `<h1>Low Stock Alert</h1><p>Stock for "<b>${item.item_name}</b>" in "<b>${item.inventory_name}</b>" is low.</p><ul><li>Current Quantity: <b>${newQuantity}</b></li><li>Threshold: <b>${threshold}</b></li><li>Last updated by: ${requesterName}</li></ul>`
                    };
                    await transporter.sendMail(mailOptions);
                    console.log(`Low stock notification sent to: ${adminEmails.join(', ')}`);

                // Condition Check if stock was low/threshold AND is now above threshold
                } else if (originalQuantity <= threshold && newQuantity > threshold) {
                    console.log(`Stock restored for item "${item.item_name}". Notifying admins...`);
                    const mailOptions = {
                        from: process.env.EMAIL_USER,
                        to: adminEmails.join(', '),
                        subject: `Stock Restored Alert: ${item.item_name}`,
                        html: `<h1>Stock Restored Alert</h1><p>Stock for "<b>${item.item_name}</b>" in "<b>${item.inventory_name}</b>" is now above the threshold.</p><ul><li>Current Quantity: <b>${newQuantity}</b></li><li>Threshold: <b>${threshold}</b></li><li>Last updated by: ${requesterName}</li></ul>`
                    };
                    await transporter.sendMail(mailOptions);
                    console.log(`Stock restored notification sent to: ${adminEmails.join(', ')}`);
                }
            } else {
                 console.log("No organization admins found to notify.");
            }
        } catch (notificationError) {
            console.error("Error sending threshold notification:", notificationError);
        }

        res.redirect(`/inventories/${inventoryId}?teamId=${teamId}`);

    } catch (error) {
        if (connection && connection.connection._closing === false) await connection.rollback();
        console.error("Error updating stock:", error);
        res.status(500).send("Failed to update stock.");
    } finally {
        if (connection && connection.connection._closing === false) connection.release();
    }
});
app.get('/inventories/:inventoryId', authenticateToken, async (req, res) => {
    const { inventoryId } = req.params;
    const { teamId } = req.query; // Get teamId from query string
    const requesterId = req.user.id;

    if (!teamId) {
        return res.status(400).send("Team ID is missing from query parameters.");
    }

    try {
        const securitySql = `
            SELECT ia.team_id, r_org.role_name as org_role, r_team.role_name as team_role
            FROM INVENTORY_ASSIGNMENTS ia
            LEFT JOIN ORGANIZATION_MEMBERS om ON ia.org_id = om.org_id AND om.user_id = ? 
            LEFT JOIN ROLES r_org ON om.role_id = r_org.role_id
            LEFT JOIN TEAM_MEMBERS tm ON ia.team_id = tm.team_id AND tm.user_id = ?
            LEFT JOIN ROLES r_team ON tm.role_id = r_team.role_id
            WHERE ia.inventory_id = ? AND ia.team_id = ?`;
        
        const [invOrg] = await dbPool.execute('SELECT org_id FROM INVENTORIES WHERE inventory_id = ?', [inventoryId]);
         if (invOrg.length === 0) return res.status(404).send("Inventory not found.");
         const orgId = invOrg[0].org_id;

         const secureCheckSql = `
            SELECT ia.team_id, r_org.role_name as org_role, r_team.role_name as team_role
            FROM INVENTORY_ASSIGNMENTS ia
            JOIN TEAMS t ON ia.team_id = t.team_id
            LEFT JOIN ORGANIZATION_MEMBERS om ON t.org_id = om.org_id AND om.user_id = ? 
            LEFT JOIN ROLES r_org ON om.role_id = r_org.role_id
            LEFT JOIN TEAM_MEMBERS tm ON ia.team_id = tm.team_id AND tm.user_id = ?
            LEFT JOIN ROLES r_team ON tm.role_id = r_team.role_id
            WHERE ia.inventory_id = ? AND ia.team_id = ? AND t.org_id = ?`;

        const [permissionRows] = await dbPool.execute(secureCheckSql, [requesterId, requesterId, inventoryId, teamId, orgId]);

        if (permissionRows.length === 0) {
             // Check if user is at least a member of the team assigned
             const memberCheckSql = `SELECT tm.user_id FROM TEAM_MEMBERS tm JOIN INVENTORY_ASSIGNMENTS ia ON tm.team_id = ia.team_id WHERE tm.user_id = ? AND ia.inventory_id = ? AND tm.team_id = ?`;
             const [memberCheck] = await dbPool.execute(memberCheckSql, [requesterId, inventoryId, teamId]);
             if (memberCheck.length === 0) {
                return res.status(403).send("Forbidden: You do not have access to this inventory via this team.");
             }
             // User is a member but maybe not admin - proceed but userIsAdmin will be false
        }


        // Determine if user has admin rights
        const orgRole = permissionRows.length > 0 ? permissionRows[0].org_role : null;
        const teamRole = permissionRows.length > 0 ? permissionRows[0].team_role : null;
        const userIsAdmin = (orgRole === 'Owner' || orgRole === 'Admin' || teamRole === 'Team Admin');

        // Fetch inventory details and items
        const [inventories] = await dbPool.execute('SELECT inventory_id, inventory_name FROM INVENTORIES WHERE inventory_id = ?', [inventoryId]);
        if (inventories.length === 0) return res.status(404).send("Inventory not found.");
        
        const [items] = await dbPool.execute('SELECT * FROM INVENTORY_ITEMS WHERE inventory_id = ? ORDER BY item_name', [inventoryId]);

        res.render('inventory-management', {
            inventory: inventories[0],
            items: items,
            teamId: teamId,
            userIsAdmin: userIsAdmin // Pass admin status to the view
        });
    } catch (error) {
        console.error("Error fetching inventory page:", error);
        res.status(500).send("Failed to load inventory page.");
    }
});



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

app.post('/inventories/:inventoryId/delete', authenticateToken, async (req, res) => {
    const { inventoryId } = req.params;
    // New confirmation_name field from the form
    const { teamId, confirmation_name } = req.body;
    const requesterId = req.user.id;

    if (!teamId || !confirmation_name) {
        return res.status(400).send("Missing required information.");
    }

    try {
        
        const [teams] = await dbPool.execute('SELECT org_id FROM TEAMS WHERE team_id = ?', [teamId]);
        if (teams.length === 0) return res.status(404).send("Associated team not found.");
        const orgId = teams[0].org_id;

        const [orgRoleRows] = await dbPool.execute(`SELECT r.role_name FROM ORGANIZATION_MEMBERS om JOIN ROLES r ON om.role_id = r.role_id WHERE om.user_id = ? AND om.org_id = ?`, [requesterId, orgId]);
        const [teamRoleRows] = await dbPool.execute(`SELECT r.role_name FROM TEAM_MEMBERS tm JOIN ROLES r ON tm.role_id = r.role_id WHERE tm.user_id = ? AND tm.team_id = ?`, [requesterId, teamId]);
        
        const orgRole = orgRoleRows.length > 0 ? orgRoleRows[0].role_name : null;
        const teamRole = teamRoleRows.length > 0 ? teamRoleRows[0].role_name : null;

        if (orgRole !== 'Owner' && orgRole !== 'Admin' && teamRole !== 'Team Admin') {
            return res.status(403).send("Forbidden: You do not have permission to delete inventories for this team.");
        }

        
        const [inventories] = await dbPool.execute('SELECT inventory_name FROM INVENTORIES WHERE inventory_id = ?', [inventoryId]);
        if (inventories.length === 0) {
            return res.status(404).send("Inventory not found.");
        }

        if (inventories[0].inventory_name !== confirmation_name) {
            return res.status(400).send("Confirmation name does not match. Deletion aborted.");
        }

        // All checks passed. Proceed with deletion.
        await dbPool.execute('DELETE FROM INVENTORIES WHERE inventory_id = ?', [inventoryId]);

        res.redirect(`/teams/${teamId}`);

    } catch (error) {
        console.error("Error deleting inventory:", error);
        res.status(500).send("Failed to delete inventory.");
    }
});

app.post('/items/:itemId/delete', authenticateToken, async (req, res) => {
    const { itemId } = req.params;
    const { inventoryId, teamId } = req.body; // Passed from hidden fields
    const requesterId = req.user.id;

    if (!inventoryId || !teamId) {
        return res.status(400).send("Missing required IDs for redirection or security check.");
    }

    try {
         // --- Security Check (Similar to the GET route) ---
         const [invOrg] = await dbPool.execute('SELECT org_id FROM INVENTORIES WHERE inventory_id = ?', [inventoryId]);
         if (invOrg.length === 0) return res.status(404).send("Inventory not found.");
         const orgId = invOrg[0].org_id;

         const secureCheckSql = `
            SELECT ia.team_id, r_org.role_name as org_role, r_team.role_name as team_role
            FROM INVENTORY_ASSIGNMENTS ia
            JOIN TEAMS t ON ia.team_id = t.team_id
            LEFT JOIN ORGANIZATION_MEMBERS om ON t.org_id = om.org_id AND om.user_id = ? 
            LEFT JOIN ROLES r_org ON om.role_id = r_org.role_id
            LEFT JOIN TEAM_MEMBERS tm ON ia.team_id = tm.team_id AND tm.user_id = ?
            LEFT JOIN ROLES r_team ON tm.role_id = r_team.role_id
            WHERE ia.inventory_id = ? AND ia.team_id = ? AND t.org_id = ?`;

        const [permissionRows] = await dbPool.execute(secureCheckSql, [requesterId, requesterId, inventoryId, teamId, orgId]);

        const orgRole = permissionRows.length > 0 ? permissionRows[0].org_role : null;
        const teamRole = permissionRows.length > 0 ? permissionRows[0].team_role : null;
        
        if (orgRole !== 'Owner' && orgRole !== 'Admin' && teamRole !== 'Team Admin') {
            return res.status(403).send("Forbidden: You do not have permission to delete items from this inventory.");
        }
        await dbPool.execute('DELETE FROM INVENTORY_ITEMS WHERE item_id = ?', [itemId]);

        // Redirect back to the inventory management page
        res.redirect(`/inventories/${inventoryId}?teamId=${teamId}`);

    } catch (error) {
        console.error("Error deleting item:", error);
        res.status(500).send("Failed to delete item.");
    }
});


app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

// app.listen(PORT, () => {
//     console.log(`Server is running on http://localhost:${PORT}`);
// });
//module.exports.handler = serverless(app, {
//  base: 'default' // Tells serverless-http to strip /default from 
//});

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}

module.exports = app;
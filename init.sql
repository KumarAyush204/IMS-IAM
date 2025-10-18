-- Disable foreign key checks for safe table dropping
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS MOVEMENT_LOGS;
DROP TABLE IF EXISTS INVENTORY_ITEMS;
DROP TABLE IF EXISTS INVENTORY_ASSIGNMENTS;
DROP TABLE IF EXISTS INVENTORIES;
DROP TABLE IF EXISTS INVITATIONS;
DROP TABLE IF EXISTS TEAM_MEMBERS;
DROP TABLE IF EXISTS TEAMS;
DROP TABLE IF EXISTS ORGANIZATION_MEMBERS;
DROP TABLE IF EXISTS ORGANIZATIONS;
DROP TABLE IF EXISTS USERS;
DROP TABLE IF EXISTS ROLES;

-- Re-enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1;

-- 1. USERS TABLE: Stores individual user accounts
CREATE TABLE USERS (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. ORGANIZATIONS TABLE: The top-level container for everything
CREATE TABLE ORGANIZATIONS (
    org_id INT PRIMARY KEY AUTO_INCREMENT,
    org_name VARCHAR(255) NOT NULL,
    owner_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES USERS(user_id)
);

-- 3. ROLES TABLE: Defines all possible roles for both scopes
CREATE TABLE ROLES (
    role_id INT PRIMARY KEY AUTO_INCREMENT,
    role_name VARCHAR(50) NOT NULL,
    scope ENUM('organization', 'team') NOT NULL,
    permissions JSON,
    UNIQUE(role_name, scope)
);

-- 4. ORGANIZATION_MEMBERS TABLE: Links users to organizations with a specific role
CREATE TABLE ORGANIZATION_MEMBERS (
    org_id INT NOT NULL,
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES ORGANIZATIONS(org_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES ROLES(role_id)
);

-- 5. TEAMS TABLE: Groups of users within an organization
CREATE TABLE TEAMS (
    team_id INT PRIMARY KEY AUTO_INCREMENT,
    team_name VARCHAR(255) NOT NULL,
    org_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES ORGANIZATIONS(org_id) ON DELETE CASCADE
);

-- 6. TEAM_MEMBERS TABLE: Links users to teams with a specific team-level role
CREATE TABLE TEAM_MEMBERS (
    team_id INT NOT NULL,
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (team_id, user_id),
    FOREIGN KEY (team_id) REFERENCES TEAMS(team_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES ROLES(role_id)
);

-- 7. INVENTORIES TABLE: Collections of items owned by an organization
CREATE TABLE INVENTORIES (
    inventory_id INT PRIMARY KEY AUTO_INCREMENT,
    inventory_name VARCHAR(255) NOT NULL,
    description TEXT,
    org_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES ORGANIZATIONS(org_id) ON DELETE CASCADE
);

-- 8. INVENTORY_ASSIGNMENTS TABLE: Links teams to inventories they can manage
CREATE TABLE INVENTORY_ASSIGNMENTS (
    inventory_id INT NOT NULL,
    team_id INT NOT NULL,
    PRIMARY KEY (inventory_id, team_id),
    FOREIGN KEY (inventory_id) REFERENCES INVENTORIES(inventory_id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES TEAMS(team_id) ON DELETE CASCADE
);

-- 9. INVENTORY_ITEMS TABLE: Individual products within an inventory
CREATE TABLE INVENTORY_ITEMS (
    item_id INT PRIMARY KEY AUTO_INCREMENT,
    inventory_id INT NOT NULL,
    item_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    quantity INT NOT NULL DEFAULT 0,
    threshold INT NOT NULL DEFAULT 10,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_id) REFERENCES INVENTORIES(inventory_id) ON DELETE CASCADE
);

-- 10. MOVEMENT_LOGS TABLE: Tracks all actions performed on inventory items
CREATE TABLE MOVEMENT_LOGS (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    item_id INT NOT NULL,
    user_id INT NOT NULL,
    action ENUM('add', 'remove', 'edit', 'transfer') NOT NULL,
    quantity_change INT NOT NULL,
    notes TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES INVENTORY_ITEMS(item_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES USERS(user_id)
);

-- 11. INVITATIONS TABLE: Stores pending invitations to an organization
CREATE TABLE INVITATIONS (
    invitation_id INT PRIMARY KEY AUTO_INCREMENT,
    org_id INT NOT NULL,
    invited_email VARCHAR(255) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    status ENUM('pending', 'accepted', 'declined', 'expired') NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES ORGANIZATIONS(org_id) ON DELETE CASCADE
);
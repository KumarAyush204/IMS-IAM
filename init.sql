-- ⭐️ Step 1: Disable foreign key checks to break the circular dependency for dropping tables.
SET FOREIGN_KEY_CHECKS = 0;

-- Drop all tables. The order is less critical now, but this is good practice.
DROP TABLE IF EXISTS THRESHOLD_SETTINGS;
DROP TABLE IF EXISTS NOTIFICATIONS;
DROP TABLE IF EXISTS STOCK_LOGS;
DROP TABLE IF EXISTS PRODUCTS;
DROP TABLE IF EXISTS INVENTORY_ASSIGNMENTS;
DROP TABLE IF EXISTS INVENTORY;
DROP TABLE IF EXISTS TEAM_MEMBERS;
DROP TABLE IF EXISTS TEAMS;
DROP TABLE IF EXISTS USERS;
DROP TABLE IF EXISTS ROLES;

-- ⭐️ Step 2: Re-enable foreign key checks to ensure data integrity for the new tables.
SET FOREIGN_KEY_CHECKS = 1;


-- 1. ROLES TABLE: Defines user roles like 'Owner', 'Manager'
CREATE TABLE ROLES (
    role_id INT PRIMARY KEY AUTO_INCREMENT,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    permissions JSON
);

-- 2. USERS TABLE: Stores user accounts
-- team_id is created as nullable initially to avoid an error before the TEAMS table exists.
CREATE TABLE USERS (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    team_id INT,
    status ENUM('active', 'inactive') NOT NULL DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES ROLES(role_id)
);

-- 3. TEAMS TABLE: Defines teams, each with an owner
CREATE TABLE TEAMS (
    team_id INT PRIMARY KEY AUTO_INCREMENT,
    team_name VARCHAR(255) NOT NULL,
    owner_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES USERS(user_id)
);

-- Now, add the foreign key from USERS to TEAMS to complete the circular reference.
ALTER TABLE USERS ADD CONSTRAINT fk_user_team FOREIGN KEY (team_id) REFERENCES TEAMS(team_id);

-- 4. TEAM_MEMBERS TABLE: Junction table for many-to-many relationship
CREATE TABLE TEAM_MEMBERS (
    id INT PRIMARY KEY AUTO_INCREMENT,
    team_id INT NOT NULL,
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES TEAMS(team_id),
    FOREIGN KEY (user_id) REFERENCES USERS(user_id),
    FOREIGN KEY (role_id) REFERENCES ROLES(role_id),
    UNIQUE(team_id, user_id)
);

-- 5. INVENTORY TABLE
CREATE TABLE INVENTORY (
    inventory_id INT PRIMARY KEY AUTO_INCREMENT,
    inventory_name VARCHAR(255) NOT NULL,
    description TEXT,
    team_id INT NOT NULL,
    created_by INT NOT NULL,
    created_role ENUM('owner', 'manager') NOT NULL,
    status ENUM('active', 'archived') NOT NULL DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES TEAMS(team_id),
    FOREIGN KEY (created_by) REFERENCES USERS(user_id)
);

-- 6. INVENTORY_ASSIGNMENTS TABLE
CREATE TABLE INVENTORY_ASSIGNMENTS (
    assignment_id INT PRIMARY KEY AUTO_INCREMENT,
    team_id INT NOT NULL,
    inventory_id INT NOT NULL,
    permissions JSON,
    FOREIGN KEY (team_id) REFERENCES TEAMS(team_id),
    FOREIGN KEY (inventory_id) REFERENCES INVENTORY(inventory_id),
    UNIQUE(team_id, inventory_id)
);

-- 7. PRODUCTS TABLE
CREATE TABLE PRODUCTS (
    product_id INT PRIMARY KEY AUTO_INCREMENT,
    inventory_id INT NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    sku VARCHAR(100) UNIQUE,
    quantity INT NOT NULL DEFAULT 0,
    price DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    threshold INT NOT NULL DEFAULT 10,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_id) REFERENCES INVENTORY(inventory_id) ON DELETE CASCADE
);

-- 8. STOCK_LOGS TABLE
CREATE TABLE STOCK_LOGS (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    product_id INT NOT NULL,
    user_id INT NOT NULL,
    action ENUM('add', 'remove', 'edit') NOT NULL,
    quantity_change INT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES PRODUCTS(product_id),
    FOREIGN KEY (user_id) REFERENCES USERS(user_id)
);

-- 9. NOTIFICATIONS TABLE
CREATE TABLE NOTIFICATIONS (
    notification_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    type ENUM('threshold', 'system', 'team') NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES USERS(user_id)
);

-- 10. THRESHOLD_SETTINGS TABLE
CREATE TABLE THRESHOLD_SETTINGS (
    setting_id INT PRIMARY KEY AUTO_INCREMENT,
    product_id INT NOT NULL,
    threshold_value INT NOT NULL,
    notify_user_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES PRODUCTS(product_id),
    FOREIGN KEY (notify_user_id) REFERENCES USERS(user_id),
    UNIQUE(product_id, notify_user_id)
);
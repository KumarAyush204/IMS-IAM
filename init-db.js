// Import required modules
const fs = require('fs').promises;
const mysql = require('mysql2/promise');
require('dotenv').config();

// Main function to run the initialization
async function initializeDatabase() {
  let connection;
  try {
    // Create a connection to the MySQL server (without specifying a database)
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      port: process.env.DB_PORT || 3306,
      multipleStatements: true // Allow multiple SQL statements in one query
    });

    const dbName = process.env.DB_NAME;
    console.log('✅ Connection to MySQL server successful.');

    // Create the database if it doesn't exist
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\`;`);
    console.log(`✅ Database '${dbName}' is ready.`);

    // Switch to the newly created database
    await connection.changeUser({ database: dbName });
    console.log(`✅ Switched to database '${dbName}'.`);

    // Read the SQL file
    const sqlScript = await fs.readFile('init.sql', 'utf8');
    console.log('📄 Reading SQL script...');

    // Execute the SQL script to create tables
    await connection.query(sqlScript);
    console.log('🚀 Database schema created successfully!');

    // --- Seed Default Roles ---
    console.log('🌱 Seeding default roles...');
    const defaultRoles = [
        { role_id: 1, role_name: 'Owner', permissions: '["*"]' },
        { role_id: 2, role_name: 'Manager', permissions: '["create_inventory", "view_stock", "edit_stock"]' },
        { role_id: 3, role_name: 'Viewer', permissions: '["view_stock"]' }
    ];
    
    const insertRoleSql = `
      INSERT INTO ROLES (role_id, role_name, permissions) 
      VALUES (?, ?, ?) 
      ON DUPLICATE KEY UPDATE role_name=VALUES(role_name), permissions=VALUES(permissions);
    `;

    for (const role of defaultRoles) {
        await connection.execute(insertRoleSql, [role.role_id, role.role_name, role.permissions]);
    }

    console.log('✅ Default roles seeded successfully.');

  } catch (error) {
    console.error('❌ An error occurred during database initialization:');
    console.error(error);
    process.exit(1); // Exit with an error code
  } finally {
    if (connection) {
      await connection.end();
      console.log('👋 Connection closed.');
    }
  }
}

// Run the function
initializeDatabase();
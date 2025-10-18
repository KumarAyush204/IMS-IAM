const fs = require('fs').promises;
const mysql = require('mysql2/promise');
require('dotenv').config();

async function initializeDatabase() {
  let connection;
  try {
    // Connect to the MySQL server
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      port: process.env.DB_PORT || 3306,
      multipleStatements: true 
    });

    const dbName = process.env.DB_NAME;
    console.log('✅ Connection to MySQL server successful.');

    // Create and select the database
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\`;`);
    await connection.query(`USE \`${dbName}\`;`);
    console.log(`✅ Database '${dbName}' is ready.`);

    // Execute the schema creation script
    const sqlScript = await fs.readFile('init.sql', 'utf8');
    await connection.query(sqlScript);
    console.log('🚀 Database schema created successfully!');

    // Seed the ROLES table with default roles
    console.log('🌱 Seeding default roles...');
    const seedRolesSQL = `
      INSERT INTO ROLES (role_id, role_name, scope) VALUES
      (1, 'Owner', 'organization'),
      (2, 'Admin', 'organization'),
      (3, 'Member', 'organization'),
      (4, 'Team Admin', 'team'),
      (5, 'Team Member', 'team')
      ON DUPLICATE KEY UPDATE role_name=VALUES(role_name);
    `;
    await connection.query(seedRolesSQL);
    console.log('✅ Default roles seeded successfully.');

  } catch (error) {
    console.error('❌ An error occurred during database initialization:');
    console.error(error);
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
      console.log('👋 Connection closed.');
    }
  }
}

initializeDatabase();
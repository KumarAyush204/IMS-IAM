const Sequelize = require("sequelize"); // Import the default export
const dotenv = require("dotenv");

dotenv.config(); // Load environment variables from .env file

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: process.env.DB_DIALECT,
    logging: false,
  }
);

module.exports = sequelize;

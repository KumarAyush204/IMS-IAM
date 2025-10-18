const { Sequelize, DataTypes } = require("sequelize"); 
const sequelize = require("../config/db.js");

// 1. USERS TABLE
const User = sequelize.define("User", {
  user_id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: DataTypes.STRING,
  email: { type: DataTypes.STRING, unique: true },
  password_hash: DataTypes.STRING,
  role_id: DataTypes.INTEGER,
  team_id: DataTypes.INTEGER,
  status: { type: DataTypes.ENUM("active", "inactive"), defaultValue: "active" },
  created_at: { type: DataTypes.DATE, defaultValue: Sequelize.NOW }
}, { tableName: "users", timestamps: false });

// ... All other model definitions remain the same

// Relationships
Role.hasMany(User, { foreignKey: "role_id" });
User.belongsTo(Role, { foreignKey: "role_id" });

Team.hasMany(User, { foreignKey: "team_id" });
User.belongsTo(Team, { foreignKey: "team_id" });

Inventory.hasMany(Product, { foreignKey: "inventory_id" });
Product.belongsTo(Inventory, { foreignKey: "inventory_id" });

Product.hasMany(StockLog, { foreignKey: "product_id" });
StockLog.belongsTo(Product, { foreignKey: "product_id" });

User.hasMany(StockLog, { foreignKey: "user_id" });
User.hasMany(Notification, { foreignKey: "user_id" });
User.hasMany(ThresholdSetting, { foreignKey: "notify_user_id" });

// Export all models in a single object
module.exports = {
  User,
  Role,
  Team,
  TeamMember,
  Inventory,
  InventoryAssignment,
  Product,
  StockLog,
  Notification,
  ThresholdSetting,
};

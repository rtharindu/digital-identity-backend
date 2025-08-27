const mongoose = require('mongoose');

const userRoleSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  userId: { type: String, required: true },
  role: { type: String, required: true },
  // Add other fields as needed
});

module.exports = mongoose.model('UserRole', userRoleSchema);

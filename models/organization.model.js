const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  // Add other fields as needed
});

module.exports = mongoose.model('Organization', organizationSchema);

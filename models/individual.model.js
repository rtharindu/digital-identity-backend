const mongoose = require('mongoose');

const individualSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  // Add other fields as needed
});

module.exports = mongoose.model('Individual', individualSchema);

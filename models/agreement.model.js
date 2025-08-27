const mongoose = require('mongoose');

const agreementSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  href: String,
  status: String,
  agreementType: String,
  engagedParty: [Object],
  relatedParty: [Object],
  createdDate: Date,
  updatedDate: Date,
  audit: [Object],
  // Add other fields as needed
});

module.exports = mongoose.model('Agreement', agreementSchema);

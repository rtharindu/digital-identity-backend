const Organization = require('../models/organization.model');

exports.createOrganization = async (req, res) => {
  try {
    const organization = new Organization(req.body);
    const saved = await organization.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getAllOrganizations = async (req, res) => {
  try {
    const organizations = await Organization.find();
    res.json(organizations);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getOrganizationById = async (req, res) => {
  try {
    const organization = await Organization.findOne({ id: req.params.id });
    if (!organization) return res.status(404).json({ message: 'Organization not found' });
    res.json(organization);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.updateOrganization = async (req, res) => {
  try {
    const organization = await Organization.findOne({ id: req.params.id });
    if (!organization) return res.status(404).json({ message: 'Organization not found' });
    Object.assign(organization, req.body);
    const updated = await organization.save();
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.deleteOrganization = async (req, res) => {
  try {
    const deleted = await Organization.findOneAndDelete({ id: req.params.id });
    if (!deleted) return res.status(404).json({ message: 'Organization not found' });
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

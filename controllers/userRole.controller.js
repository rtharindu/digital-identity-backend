const UserRole = require('../models/userRole.model');

exports.createUserRole = async (req, res) => {
  try {
    const userRole = new UserRole(req.body);
    const saved = await userRole.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getAllUserRoles = async (req, res) => {
  try {
    const userRoles = await UserRole.find();
    res.json(userRoles);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getUserRoleById = async (req, res) => {
  try {
    const userRole = await UserRole.findOne({ id: req.params.id });
    if (!userRole) return res.status(404).json({ message: 'UserRole not found' });
    res.json(userRole);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.updateUserRole = async (req, res) => {
  try {
    const userRole = await UserRole.findOne({ id: req.params.id });
    if (!userRole) return res.status(404).json({ message: 'UserRole not found' });
    Object.assign(userRole, req.body);
    const updated = await userRole.save();
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.deleteUserRole = async (req, res) => {
  try {
    const deleted = await UserRole.findOneAndDelete({ id: req.params.id });
    if (!deleted) return res.status(404).json({ message: 'UserRole not found' });
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

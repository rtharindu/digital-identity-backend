const Individual = require('../models/individual.model');

exports.createIndividual = async (req, res) => {
  try {
    const individual = new Individual(req.body);
    const saved = await individual.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getAllIndividuals = async (req, res) => {
  try {
    const individuals = await Individual.find();
    res.json(individuals);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getIndividualById = async (req, res) => {
  try {
    const individual = await Individual.findOne({ id: req.params.id });
    if (!individual) return res.status(404).json({ message: 'Individual not found' });
    res.json(individual);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.updateIndividual = async (req, res) => {
  try {
    const individual = await Individual.findOne({ id: req.params.id });
    if (!individual) return res.status(404).json({ message: 'Individual not found' });
    Object.assign(individual, req.body);
    const updated = await individual.save();
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.deleteIndividual = async (req, res) => {
  try {
    const deleted = await Individual.findOneAndDelete({ id: req.params.id });
    if (!deleted) return res.status(404).json({ message: 'Individual not found' });
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

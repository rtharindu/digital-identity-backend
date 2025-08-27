const { v4: uuidv4 } = require('uuid');
const Agreement = require('../models/agreement.model');
const { agreementSchema } = require('../validators/agreement');
const BASE_URL = process.env.FRONTEND_URL ? `${process.env.FRONTEND_URL}/agreements` : '/agreements';

exports.createAgreement = async (req, res) => {
  const { error } = agreementSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  try {
    const now = new Date();
    const agreementId = uuidv4();
    const newAgreement = new Agreement({
      id: agreementId,
      href: `${BASE_URL}/${agreementId}`,
      ...req.body,
      status: 'in process',
      createdDate: now,
      updatedDate: null,
      audit: [{
        timestamp: now,
        action: 'created',
        by: req.body.relatedParty?.[0]?.id || 'system'
      }]
    });
    const savedAgreement = await newAgreement.save();
    res.status(201).json(savedAgreement);
  } catch (err) {
    if (err.code === 11000 && err.keyPattern?.id) {
      return res.status(409).json({ message: 'Agreement ID conflict (UUID)' });
    }
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getAgreementById = async (req, res) => {
  try {
    const agreement = await Agreement.findOne({ id: req.params.id });
    if (!agreement) return res.status(404).json({ message: 'Agreement not found' });
    res.json(agreement);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getAllAgreements = async (req, res) => {
  try {
    const { status, engagedPartyId, agreementType, offset = 0, limit = 20 } = req.query;
    const query = {};
    if (status) query.status = status;
    if (agreementType) query.agreementType = agreementType;
    if (engagedPartyId) query.engagedParty = { $elemMatch: { id: engagedPartyId } };

    const skip = parseInt(offset);
    const take = parseInt(limit);
    const agreements = await Agreement.find(query).skip(skip).limit(take);
    res.json(agreements);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.updateAgreement = async (req, res) => {
  try {
    const agreement = await Agreement.findOne({ id: req.params.id });
    if (!agreement) return res.status(404).json({ message: 'Agreement not found' });

    const now = new Date();
    Object.assign(agreement, req.body, { updatedDate: now });
    agreement.audit.push({
      timestamp: now,
      action: 'updated',
      by: req.body.relatedParty?.[0]?.id || 'system'
    });

    const updatedAgreement = await agreement.save();
    res.json(updatedAgreement);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.deleteAgreement = async (req, res) => {
  try {
    const deleted = await Agreement.findOneAndDelete({ id: req.params.id });
    if (!deleted) {
      return res.status(404).json({ message: 'Agreement not found' });
    }
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

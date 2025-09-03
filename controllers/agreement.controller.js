const { v4: uuidv4 } = require('uuid');
const Agreement = require('../models/agreement.model');
const { agreementSchema } = require('../validators/agreement');
const BASE_URL = process.env.FRONTEND_URL ? `${process.env.FRONTEND_URL}/agreements` : '/agreements';

// Allowed fields for updates to prevent unauthorized field modifications
const ALLOWED_UPDATE_FIELDS = [
  'status',
  'agreementType',
  'engagedParty',
  'relatedParty'
];

// Helper function to validate UUID format
const isValidUUID = (uuid) => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
};

// Helper function to validate agreement type
const isValidAgreementType = (type) => {
  return typeof type === 'string' && /^[a-zA-Z0-9\s\-_.]+$/.test(type);
};

// Helper function to validate party array
const validatePartyArray = (parties) => {
  if (!Array.isArray(parties)) return null;
  
  const validParties = parties.filter(party => 
    party && typeof party === 'object' && 
    party.id && isValidUUID(party.id)
  );
  
  return validParties.length > 0 ? validParties : null;
};

// Sanitize and validate query parameters
const sanitizeQueryParams = (params) => {
  const { status, engagedPartyId, agreementType, offset = 0, limit = 20 } = params;
  
  // Validate and sanitize status
  const validStatuses = ['in process', 'active', 'suspended', 'terminated'];
  const sanitizedStatus = validStatuses.includes(status) ? status : null;
  
  // Validate and sanitize agreementType (allow only alphanumeric and basic punctuation)
  const sanitizedAgreementType = agreementType && isValidAgreementType(agreementType) 
    ? agreementType.trim() 
    : null;
  
  // Validate and sanitize engagedPartyId (UUID format)
  const sanitizedEngagedPartyId = engagedPartyId && isValidUUID(engagedPartyId) 
    ? engagedPartyId 
    : null;
  
  // Validate and sanitize pagination parameters
  const sanitizedOffset = Math.max(0, parseInt(offset) || 0);
  const sanitizedLimit = Math.min(100, Math.max(1, parseInt(limit) || 20));
  
  return {
    status: sanitizedStatus,
    engagedPartyId: sanitizedEngagedPartyId,
    agreementType: sanitizedAgreementType,
    offset: sanitizedOffset,
    limit: sanitizedLimit
  };
};

// Validate and sanitize update data
const sanitizeUpdateData = (data) => {
  const sanitized = {};
  
  // Only allow updates to permitted fields
  ALLOWED_UPDATE_FIELDS.forEach(field => {
    if (data[field] === undefined) return;
    
    if (field === 'status') {
      const validStatuses = ['in process', 'active', 'suspended', 'terminated'];
      if (validStatuses.includes(data[field])) {
        sanitized[field] = data[field];
      }
    } else if (field === 'agreementType') {
      if (isValidAgreementType(data[field])) {
        sanitized[field] = data[field].trim();
      }
    } else if (field === 'engagedParty' || field === 'relatedParty') {
      const validParties = validatePartyArray(data[field]);
      if (validParties) {
        sanitized[field] = validParties;
      }
    }
  });
  
  return sanitized;
};

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
    // Validate that the ID parameter is a valid UUID
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ message: 'Invalid agreement ID format' });
    }
    
    const agreement = await Agreement.findOne({ id: req.params.id });
    if (!agreement) return res.status(404).json({ message: 'Agreement not found' });
    res.json(agreement);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.getAllAgreements = async (req, res) => {
  try {
    // Sanitize and validate all query parameters
    const sanitizedParams = sanitizeQueryParams(req.query);
    
    // Build query object with only sanitized values
    const query = {};
    if (sanitizedParams.status) query.status = sanitizedParams.status;
    if (sanitizedParams.agreementType) query.agreementType = sanitizedParams.agreementType;
    if (sanitizedParams.engagedPartyId) {
      query.engagedParty = { $elemMatch: { id: sanitizedParams.engagedPartyId } };
    }

    const agreements = await Agreement.find(query)
      .skip(sanitizedParams.offset)
      .limit(sanitizedParams.limit);
    res.json(agreements);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.updateAgreement = async (req, res) => {
  try {
    // Validate that the ID parameter is a valid UUID
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ message: 'Invalid agreement ID format' });
    }

    const agreement = await Agreement.findOne({ id: req.params.id });
    if (!agreement) return res.status(404).json({ message: 'Agreement not found' });

    // Sanitize and validate update data
    const sanitizedData = sanitizeUpdateData(req.body);
    
    // Only update allowed fields with sanitized data
    Object.keys(sanitizedData).forEach(key => {
      agreement[key] = sanitizedData[key];
    });
    
    const now = new Date();
    agreement.updatedDate = now;
    
    // Safely add audit entry with validated data
    const auditBy = req.body.relatedParty?.[0]?.id;
    const validAuditBy = auditBy && isValidUUID(auditBy) ? auditBy : 'system';
    
    agreement.audit.push({
      timestamp: now,
      action: 'updated',
      by: validAuditBy
    });

    const updatedAgreement = await agreement.save();
    res.json(updatedAgreement);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.deleteAgreement = async (req, res) => {
  try {
    // Validate that the ID parameter is a valid UUID
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ message: 'Invalid agreement ID format' });
    }
    
    const deleted = await Agreement.findOneAndDelete({ id: req.params.id });
    if (!deleted) {
      return res.status(404).json({ message: 'Agreement not found' });
    }
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

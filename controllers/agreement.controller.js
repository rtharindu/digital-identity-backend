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

// Helper function to ensure parameter type safety
const ensureStringType = (value) => {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return null; // Reject objects, arrays, and other complex types
};

// Helper function to ensure number type safety
const ensureNumberType = (value, min = 0, max = Infinity) => {
  if (value === null || value === undefined) return null;
  const num = parseInt(value);
  if (isNaN(num)) return null;
  return Math.max(min, Math.min(max, num));
};

// Helper function to validate query object for malicious operators
const validateQueryObject = (query) => {
  const allowedOperators = ['$elemMatch'];
  const allowedFields = ['status', 'agreementType', 'engagedParty'];
  
  // Check if query contains any unexpected fields
  for (const field of Object.keys(query)) {
    if (!allowedFields.includes(field)) {
      throw new Error(`Invalid query field: ${field}`);
    }
    
    // Check if field value contains malicious operators
    const value = query[field];
    if (typeof value === 'object' && value !== null) {
      for (const operator of Object.keys(value)) {
        if (!allowedOperators.includes(operator)) {
          throw new Error(`Invalid query operator: ${operator}`);
        }
      }
    }
  }
  
  return query;
};

// Sanitize and validate query parameters
const sanitizeQueryParams = (params) => {
  // Ensure params is an object and extract with defaults
  if (!params || typeof params !== 'object') {
    return { offset: 0, limit: 20 };
  }
  
  const { status, engagedPartyId, agreementType, offset = 0, limit = 20 } = params;
  
  // Use helper functions to ensure type safety and prevent NoSQL injection
  const sanitizedStatus = ensureStringType(status);
  const sanitizedAgreementType = ensureStringType(agreementType);
  const sanitizedEngagedPartyId = ensureStringType(engagedPartyId);
  const sanitizedOffset = ensureNumberType(offset, 0, 10000); // Max 10k offset
  const sanitizedLimit = ensureNumberType(limit, 1, 100); // Max 100 items per page
  
  // Additional validation for status - only allow predefined values
  const validStatuses = ['in process', 'active', 'suspended', 'terminated'];
  const finalStatus = validStatuses.includes(sanitizedStatus) ? sanitizedStatus : null;
  
  // Additional validation for agreementType - only allow safe patterns
  const finalAgreementType = sanitizedAgreementType && isValidAgreementType(sanitizedAgreementType) 
    ? sanitizedAgreementType 
    : null;
  
  // Additional validation for engagedPartyId - only allow valid UUID format
  const finalEngagedPartyId = sanitizedEngagedPartyId && isValidUUID(sanitizedEngagedPartyId) 
    ? sanitizedEngagedPartyId 
    : null;
  
  return {
    status: finalStatus,
    engagedPartyId: finalEngagedPartyId,
    agreementType: finalAgreementType,
    offset: sanitizedOffset || 0,
    limit: sanitizedLimit || 20
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
    
    // Safely extract and validate relatedParty for audit
    const relatedPartyId = req.body.relatedParty?.[0]?.id;
    const validAuditBy = relatedPartyId && isValidUUID(relatedPartyId) ? relatedPartyId : 'system';
    
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
        by: validAuditBy
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
    
    // Build query object with explicit, safe field assignments only
    // This prevents NoSQL injection by ensuring only validated, safe values are used
    const query = {};
    
    // Status: Only allow predefined enum values (already validated in sanitizeQueryParams)
    if (sanitizedParams.status) {
      query.status = sanitizedParams.status;
    }
    
    // AgreementType: Only allow validated string patterns (already validated in sanitizeQueryParams)
    if (sanitizedParams.agreementType) {
      query.agreementType = sanitizedParams.agreementType;
    }
    
    // EngagedPartyId: Only allow valid UUID format with safe query structure
    // The UUID is already validated in sanitizeQueryParams, so we can safely use it
    if (sanitizedParams.engagedPartyId) {
      query.engagedParty = { 
        $elemMatch: { 
          id: sanitizedParams.engagedPartyId 
        } 
      };
    }

    // Validate the final query object to ensure no malicious operators are present
    const validatedQuery = validateQueryObject(query);
    
    // Execute query with validated parameters - all values are now guaranteed to be safe strings/numbers
    const agreements = await Agreement.find(validatedQuery)
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
    const relatedPartyId = req.body.relatedParty?.[0]?.id;
    const validAuditBy = relatedPartyId && isValidUUID(relatedPartyId) ? relatedPartyId : 'system';
    
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

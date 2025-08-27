const Joi = require('joi');

const agreementSchema = Joi.object({
  agreementType: Joi.string().required(),
  engagedParty: Joi.array().items(Joi.object({ id: Joi.string().required() })).required(),
  relatedParty: Joi.array().items(Joi.object({ id: Joi.string().required() })).optional(),
  // Add other fields and validation as needed
});

module.exports = { agreementSchema };

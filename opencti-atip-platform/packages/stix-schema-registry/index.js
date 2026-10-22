/**
 * STIX 2.1 Schema Registry & Envelope Validation Utility
 */

const fs = require('fs');
const path = require('path');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

const bundleSchemaPath = path.join(__dirname, 'schemas', 'stix_bundle.json');
const envelopesSchemaPath = path.join(__dirname, 'schemas', 'envelopes.json');

const bundleSchema = JSON.parse(fs.readFileSync(bundleSchemaPath, 'utf8'));
const envelopesSchema = JSON.parse(fs.readFileSync(envelopesSchemaPath, 'utf8'));

ajv.addSchema(bundleSchema, 'stix_bundle.json');
ajv.addSchema(envelopesSchema, 'envelopes.json');

const validateBundle = ajv.compile(bundleSchema);
const validateEnrichmentRequest = ajv.compile({
  $ref: 'envelopes.json#/definitions/EnrichmentRequest'
});
const validateCDCEvent = ajv.compile({
  $ref: 'envelopes.json#/definitions/GraphCDCEvent'
});

module.exports = {
  validateBundle,
  validateEnrichmentRequest,
  validateCDCEvent,
  schemas: {
    bundle: bundleSchema,
    envelopes: envelopesSchema
  }
};

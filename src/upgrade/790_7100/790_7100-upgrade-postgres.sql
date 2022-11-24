-- ALTER TABLE AcmeAuthorizationData ADD identifier TEXT;
-- ALTER TABLE AcmeAuthorizationData ADD identifierType TEXT;
-- ALTER TABLE AcmeAuthorizationData ADD expires INT8;
-- ALTER TABLE AcmeAuthorizationData ADD status TEXT;

-- DROP INDEX IF EXISTS acmeauthorizationdata_idx1;
-- CREATE INDEX acmeauthorizationdata_idx1 ON AcmeAuthorizationData (orderId,accountId,expires,status);
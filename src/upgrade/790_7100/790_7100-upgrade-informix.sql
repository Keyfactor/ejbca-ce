-- subjectDn column size is increased in ApprovalData table to conform with subjectDn in other tables e.g. UserData
-- ALTER TABLE ApprovalData MODIFY subjectDn VARCHAR(400,0);

-- ALTER TABLE AcmeAuthorizationData ADD identifier VARCHAR(255,0);
-- ALTER TABLE AcmeAuthorizationData ADD identifierType VARCHAR(20,0);
-- ALTER TABLE AcmeAuthorizationData ADD expires DECIMAL(18,0);
-- ALTER TABLE AcmeAuthorizationData ADD status VARCHAR(20,0);

-- DROP INDEX IF EXISTS acmeauthorizationdata_idx1 ONLINE;
-- CREATE INDEX acmeauthorizationdata_idx1 ON AcmeAuthorizationData (orderId,accountId,expires,status) ONLINE;
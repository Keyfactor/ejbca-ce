-- subjectDn column size is increased in ApprovalData table to conform with subjectDn in other tables e.g. UserData
-- ALTER TABLE ApprovalData MODIFY subjectDn VARCHAR(400) BINARY;

-- ALTER TABLE AcmeAuthorizationData ADD identifier VARCHAR(250) BINARY;
-- ALTER TABLE AcmeAuthorizationData ADD identifierType VARCHAR(20) BINARY;
-- ALTER TABLE AcmeAuthorizationData ADD expires BIGINT(20);
-- ALTER TABLE AcmeAuthorizationData ADD status VARCHAR(20) BINARY;

-- DROP INDEX IF EXISTS acmeauthorizationdata_idx1 ON AcmeAuthorizationData;
-- CREATE INDEX acmeauthorizationdata_idx1 ON AcmeAuthorizationData (orderId,accountId,expires,status);
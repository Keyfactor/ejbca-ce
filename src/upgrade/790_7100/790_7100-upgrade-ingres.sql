-- subjectDn column size is increased in ApprovalData table to conform with subjectDn in other tables e.g. UserData
-- ALTER TABLE ApprovalData MODIFY subjectDn VARCHAR(400);

-- ALTER TABLE AcmeAuthorizationData ADD identifier VARCHAR(256) with null;
-- ALTER TABLE AcmeAuthorizationData ADD identifierType VARCHAR(20) with null;
-- ALTER TABLE AcmeAuthorizationData ADD expires INT8 with null;
-- ALTER TABLE AcmeAuthorizationData ADD status VARCHAR(20) with null;

-- DROP INDEX acmeauthorizationdata_idx1;
-- CREATE INDEX acmeauthorizationdata_idx1 ON AcmeAuthorizationData (orderId,accountId,expires,status);
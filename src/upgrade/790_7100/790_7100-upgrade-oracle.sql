-- subjectDn column size is increased in ApprovalData table to conform with subjectDn in other tables e.g. UserData
-- ALTER TABLE ApprovalData MODIFY subjectDn VARCHAR2(400 byte);

-- ALTER TABLE AcmeAuthorizationData ADD identifier VARCHAR2(255 byte);
-- ALTER TABLE AcmeAuthorizationData ADD identifierType VARCHAR2(20 byte);
-- ALTER TABLE AcmeAuthorizationData ADD expires NUMBER(19);
-- ALTER TABLE AcmeAuthorizationData ADD status VARCHAR2(20 byte);

-- DROP INDEX acmeauthorizationdata_idx1;
-- CREATE INDEX acmeauthorizationdata_idx1 ON AcmeAuthorizationData (orderId,accountId,expires,status);
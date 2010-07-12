
-- AdminGroupData.pK was named "primkey" on JBoss because of a missing mapping file for Derby in EJBCA 3.x if not the doc/howto/create-tables-ejbca3-derby.sql file was used.
ALTER TABLE AdminGroupData ADD COLUMN pK INTEGER NOT NULL DEFAULT 0;
UPDATE AdminGroupData SET pK=primkey;
ALTER TABLE AdminGroupData DROP COLUMN primkey;
ALTER TABLE AdminGroupData ADD PRIMARY KEY(pK);

-- Perform data-type changes to have size consistency over all databases
--  CertificateData.base64Cert is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE CertificateData ADD tmpbase64Cert CLOB DEFAULT NULL;
-- UPDATE CertificateData SET tmpbase64Cert=base64Cert;
-- ALTER TABLE CertificateData DROP COLUMN base64Cert;
-- ALTER TABLE CertificateData ADD base64Cert CLOB DEFAULT NULL;
-- UPDATE CertificateData SET base64Cert=tmpbase64Cert;
-- ALTER TABLE CertificateData DROP COLUMN tmpbase64Cert;

--  KeyRecoveryData.keyData is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE KeyRecoveryData ADD tmpkeyData CLOB DEFAULT NULL;
-- UPDATE KeyRecoveryData SET tmpkeyData=keyData;
-- ALTER TABLE KeyRecoveryData DROP COLUMN keyData;
-- ALTER TABLE KeyRecoveryData ADD keyData CLOB DEFAULT NULL;
-- UPDATE KeyRecoveryData SET keyData=tmpkeyData;
-- ALTER TABLE KeyRecoveryData DROP COLUMN tmpkeyData;

--  ProtectedLogData.b64LinkedInEventIdentifiers is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE ProtectedLogData ADD tmpb64LinkedInEventIdentifiers CLOB DEFAULT NULL;
-- UPDATE ProtectedLogData SET tmpb64LinkedInEventIdentifiers=b64LinkedInEventIdentifiers;
-- ALTER TABLE ProtectedLogData DROP COLUMN b64LinkedInEventIdentifiers;
-- ALTER TABLE ProtectedLogData ADD b64LinkedInEventIdentifiers CLOB DEFAULT NULL;
-- UPDATE ProtectedLogData SET b64LinkedInEventIdentifiers=tmpb64LinkedInEventIdentifiers;
-- ALTER TABLE ProtectedLogData DROP COLUMN tmpb64LinkedInEventIdentifiers;

--  ProtectedLogData.b64Protection is currently LONG VARCHAR, but is defined as ~VARCHAR(4000) on other databases
-- ALTER TABLE ProtectedLogData ADD tmpb64Protection VARCHAR(4000) DEFAULT NULL;
-- UPDATE ProtectedLogData SET tmpb64Protection=b64Protection;
-- ALTER TABLE ProtectedLogData DROP COLUMN b64Protection;
-- ALTER TABLE ProtectedLogData ADD b64Protection VARCHAR(4000) DEFAULT NULL;
-- UPDATE ProtectedLogData SET b64Protection=tmpb64Protection;
-- ALTER TABLE ProtectedLogData DROP COLUMN tmpb64Protection;

--  ProtectedLogData.b64Signature is currently LONG VARCHAR, but is defined as ~VARCHAR(4000) on other databases
-- ALTER TABLE ProtectedLogData ADD tmpb64Signature VARCHAR(4000) DEFAULT NULL;
-- UPDATE ProtectedLogData SET tmpb64Signature=b64Signature;
-- ALTER TABLE ProtectedLogData DROP COLUMN b64Signature;
-- ALTER TABLE ProtectedLogData ADD b64Signature VARCHAR(4000) DEFAULT NULL;
-- UPDATE ProtectedLogData SET b64Signature=tmpb64Signature;
-- ALTER TABLE ProtectedLogData DROP COLUMN tmpb64Signature;

--  ProtectedLogExportData.b64Signature is currently LONG VARCHAR, but is defined as ~VARCHAR(4000) on other databases
-- ALTER TABLE ProtectedLogExportData ADD tmpb64Signature VARCHAR(4000) DEFAULT NULL;
-- UPDATE ProtectedLogExportData SET tmpb64Signature=b64Signature;
-- ALTER TABLE ProtectedLogExportData DROP COLUMN b64Signature;
-- ALTER TABLE ProtectedLogExportData ADD b64Signature VARCHAR(4000) DEFAULT NULL;
-- UPDATE ProtectedLogExportData SET b64Signature=tmpb64Signature;
-- ALTER TABLE ProtectedLogExportData DROP COLUMN tmpb64Signature;

--  ProtectedLogExportData.b64SignatureCertificate is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE ProtectedLogExportData ADD tmpb64SignatureCertificate CLOB DEFAULT NULL;
-- UPDATE ProtectedLogExportData SET tmpb64SignatureCertificate=b64SignatureCertificate;
-- ALTER TABLE ProtectedLogExportData DROP COLUMN b64SignatureCertificate;
-- ALTER TABLE ProtectedLogExportData ADD b64SignatureCertificate CLOB DEFAULT NULL;
-- UPDATE ProtectedLogExportData SET b64SignatureCertificate=tmpb64SignatureCertificate;
-- ALTER TABLE ProtectedLogExportData DROP COLUMN tmpb64SignatureCertificate;

--  ProtectedLogTokenData.b64TokenCertificate is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE ProtectedLogTokenData ADD tmpb64TokenCertificate CLOB DEFAULT NULL;
-- UPDATE ProtectedLogTokenData SET tmpb64TokenCertificate=b64TokenCertificate;
-- ALTER TABLE ProtectedLogTokenData DROP COLUMN b64TokenCertificate;
-- ALTER TABLE ProtectedLogTokenData ADD b64TokenCertificate CLOB DEFAULT NULL;
-- UPDATE ProtectedLogTokenData SET b64TokenCertificate=tmpb64TokenCertificate;
-- ALTER TABLE ProtectedLogTokenData DROP COLUMN tmpb64TokenCertificate;

--  ProtectedLogTokenData.tokenReference is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE ProtectedLogTokenData ADD tmptokenReference CLOB DEFAULT NULL;
-- UPDATE ProtectedLogTokenData SET tmptokenReference=tokenReference;
-- ALTER TABLE ProtectedLogTokenData DROP COLUMN tokenReference;
-- ALTER TABLE ProtectedLogTokenData ADD tokenReference CLOB DEFAULT NULL;
-- UPDATE ProtectedLogTokenData SET tokenReference=tmptokenReference;
-- ALTER TABLE ProtectedLogTokenData DROP COLUMN tmptokenReference;

--  PublisherData.data is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE PublisherData ADD tmpdata CLOB DEFAULT NULL;
-- UPDATE PublisherData SET tmpdata=data;
-- ALTER TABLE PublisherData DROP COLUMN data;
-- ALTER TABLE PublisherData ADD data CLOB DEFAULT NULL;
-- UPDATE PublisherData SET data=tmpdata;
-- ALTER TABLE PublisherData DROP COLUMN tmpdata;

--  PublisherQueueData.volatileData is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE PublisherQueueData ADD tmpvolatileData CLOB DEFAULT NULL;
-- UPDATE PublisherQueueData SET tmpvolatileData=volatileData;
-- ALTER TABLE PublisherQueueData DROP COLUMN volatileData;
-- ALTER TABLE PublisherQueueData ADD volatileData CLOB DEFAULT NULL;
-- UPDATE PublisherQueueData SET volatileData=tmpvolatileData;
-- ALTER TABLE PublisherQueueData DROP COLUMN tmpvolatileData;

--  ServiceData.data is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE ServiceData ADD tmpdata CLOB DEFAULT NULL;
-- UPDATE ServiceData SET tmpdata=data;
-- ALTER TABLE ServiceData DROP COLUMN data;
-- ALTER TABLE ServiceData ADD data CLOB DEFAULT NULL;
-- UPDATE ServiceData SET data=tmpdata;
-- ALTER TABLE ServiceData DROP COLUMN tmpdata;

--  UserDataSourceData.data is currently LONG VARCHAR, but is defined as CLOB on other databases
-- ALTER TABLE UserDataSourceData ADD tmpdata CLOB DEFAULT NULL;
-- UPDATE UserDataSourceData SET tmpdata=data;
-- ALTER TABLE UserDataSourceData DROP COLUMN data;
-- ALTER TABLE UserDataSourceData ADD data CLOB DEFAULT NULL;
-- UPDATE UserDataSourceData SET data=tmpdata;
-- ALTER TABLE UserDataSourceData DROP COLUMN tmpdata;


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


-- The java.lang.Integer HardTokenProfileData.id was mapped as VARCHAR(80) BINARY in EJBCA 3.x.
ALTER TABLE HardTokenProfileData MODIFY id int(11) DEFAULT 0;

-- MySQL specific: CLOBs are mapped to "longtext" and not "text". According to http://opensource.atlassian.com/projects/hibernate/browse/HHH-2669 there is no performance gain from using "text".
-- These might be kind of optional.
ALTER TABLE CAData MODIFY data longtext DEFAULT NULL;
ALTER TABLE PublisherData MODIFY data longtext DEFAULT NULL;
ALTER TABLE PublisherQueueData MODIFY volatileData longtext DEFAULT NULL;
ALTER TABLE CertificateData MODIFY base64Cert longtext DEFAULT NULL;
ALTER TABLE KeyRecoveryData MODIFY keyData longtext DEFAULT NULL;
ALTER TABLE UserDataSourceData MODIFY data longtext DEFAULT NULL;
ALTER TABLE ServiceData MODIFY data longtext DEFAULT NULL;

-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD nextRunTimeStamp bigint(20) NOT NULL DEFAULT '0';
ALTER TABLE ServiceData ADD runTimeStamp bigint(20) NOT NULL DEFAULT '0';

-- Add rowVersion column to all tables
ALTER TABLE AccessRulesData ADD COLUMN rowVersion int(11) DEFAULT 0; 
ALTER TABLE AdminEntityData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE AdminGroupData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE AdminPreferencesData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE ApprovalData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE AuthorizationTreeUpdateData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE CAData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE CRLData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE CertReqHistoryData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE CertificateData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE CertificateProfileData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE EndEntityProfileData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE GlobalConfigurationData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE HardTokenCertificateMap ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE HardTokenData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE HardTokenIssuerData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE HardTokenProfileData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE HardTokenPropertyData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE KeyRecoveryData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE LogConfigurationData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE LogEntryData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE PublisherData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE PublisherQueueData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE ServiceData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE TableProtectData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE UserData ADD COLUMN rowVersion int(11) DEFAULT 0;
ALTER TABLE UserDataSourceData ADD COLUMN rowVersion int(11) DEFAULT 0;

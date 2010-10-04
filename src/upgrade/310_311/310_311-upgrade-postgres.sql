
-- BOOLEANs on WebSphere were created as INT2 instead of "BOOLEAN". Hibernate will map this as BOOLEAN so we probably need to update this. 
--  We cannot cast INT2 to BOOLEAN so we have to work around it..
-- NOTE! This is only for WebSphere, not other application servers. Therefore we do not run them by default
--ALTER TABLE AccessRulesData ADD tmp BOOLEAN DEFAULT FALSE NOT NULL;
--UPDATE AccessRulesData SET tmp=TRUE WHERE isRecursive=1;
--ALTER TABLE AccessRulesData DROP isRecursive;
--ALTER TABLE AccessRulesData ADD isRecursive BOOLEAN DEFAULT FALSE NOT NULL;
--UPDATE AccessRulesData SET isRecursive=tmp;
--ALTER TABLE AccessRulesData DROP tmp;

--ALTER TABLE KeyRecoveryData ADD tmp BOOLEAN DEFAULT FALSE NOT NULL;
--UPDATE KeyRecoveryData SET tmp=TRUE WHERE markedAsRecoverable=1;
--ALTER TABLE KeyRecoveryData DROP markedAsRecoverable;
--ALTER TABLE KeyRecoveryData ADD markedAsRecoverable BOOLEAN DEFAULT FALSE NOT NULL;
--UPDATE KeyRecoveryData SET markedAsRecoverable=tmp;
--ALTER TABLE KeyRecoveryData DROP tmp;

-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD nextRunTimeStamp INT8 NOT NULL DEFAULT 0;
ALTER TABLE ServiceData ADD runTimeStamp INT8 NOT NULL DEFAULT 0;

-- Add rowVersion column to all tables
ALTER TABLE AccessRulesData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE AdminEntityData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE AdminGroupData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE AdminPreferencesData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE ApprovalData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE AuthorizationTreeUpdateData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE CAData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE CRLData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE CertReqHistoryData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE CertificateData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE CertificateProfileData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE EndEntityProfileData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE GlobalConfigurationData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE HardTokenCertificateMap ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE HardTokenData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE HardTokenIssuerData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE HardTokenProfileData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE HardTokenPropertyData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE KeyRecoveryData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE LogConfigurationData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE LogEntryData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE PublisherData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE PublisherQueueData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE ServiceData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE TableProtectData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE UserData ADD COLUMN rowVersion INT4 DEFAULT 0;
ALTER TABLE UserDataSourceData ADD COLUMN rowVersion INT4 DEFAULT 0;


-- Perform data-type changes to have size consistency over all databases
--  ApprovalData.approvaldata is currently VARCHAR2(4000), but is defined as CLOB on other databases
ALTER TABLE ApprovalData ADD tmpapprovaldata CLOB DEFAULT NULL;
UPDATE ApprovalData SET tmpapprovaldata=approvaldata;
ALTER TABLE ApprovalData DROP COLUMN approvaldata;
ALTER TABLE ApprovalData ADD approvaldata CLOB DEFAULT NULL;
UPDATE ApprovalData SET approvaldata=tmpapprovaldata;
ALTER TABLE ApprovalData DROP COLUMN tmpapprovaldata;

-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD nextRunTimeStamp NUMBER(19) DEFAULT 0 NOT NULL;
ALTER TABLE ServiceData ADD runTimeStamp NUMBER(19) DEFAULT 0 NOT NULL;

-- Add rowVersion column to all tables
ALTER TABLE AccessRulesData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE AdminEntityData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE AdminGroupData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE AdminPreferencesData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE ApprovalData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE AuthorizationTreeUpdateData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE CAData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE CRLData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE CertReqHistoryData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE CertificateData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE CertificateProfileData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE EndEntityProfileData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE GlobalConfigurationData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE HardTokenCertificateMap ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE HardTokenData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE HardTokenIssuerData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE HardTokenProfileData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE HardTokenPropertyData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE KeyRecoveryData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE LogConfigurationData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE LogEntryData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE ProtectedLogData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE ProtectedLogExportData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE ProtectedLogTokenData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE PublisherData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE ServiceData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE TableProtectData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE UserData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
ALTER TABLE UserDataSourceData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;

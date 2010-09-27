
-- Perform data-type changes to have size consistency over all databases
--  ApprovalData.requestdata is currently VARCHAR(8000), but is defined as CLOB on other databases
--  ApprovalData.approvaldata is currently VARCHAR(4000), but is defined as CLOB on other databases
ALTER TABLE ApprovalData ADD tmprequestdata CLOB DEFAULT NULL;
ALTER TABLE ApprovalData ADD tmpapprovaldata CLOB DEFAULT NULL;
UPDATE ApprovalData SET tmprequestdata=requestdata;
UPDATE ApprovalData SET tmpapprovaldata=approvaldata;
ALTER TABLE ApprovalData DROP COLUMN requestdata;
ALTER TABLE ApprovalData DROP COLUMN approvaldata;
ALTER TABLE ApprovalData ADD requestdata CLOB DEFAULT NULL;
ALTER TABLE ApprovalData ADD approvaldata CLOB DEFAULT NULL;
CALL SYSPROC.ADMIN_CMD('REORG TABLE ApprovalData');
UPDATE ApprovalData SET requestdata=tmprequestdata;
UPDATE ApprovalData SET approvaldata=tmpapprovaldata;
ALTER TABLE ApprovalData DROP COLUMN tmprequestdata;
ALTER TABLE ApprovalData DROP COLUMN tmpapprovaldata;
CALL SYSPROC.ADMIN_CMD('REORG TABLE ApprovalData');

--  CertificateData.base64Cert is currently VARCHAR(8000), but is defined as CLOB on other databases
ALTER TABLE CertificateData ADD tmpbase64Cert CLOB DEFAULT NULL;
UPDATE CertificateData SET tmpbase64Cert=base64Cert;
ALTER TABLE CertificateData DROP COLUMN base64Cert;
ALTER TABLE CertificateData ADD base64Cert CLOB DEFAULT NULL;
CALL SYSPROC.ADMIN_CMD('REORG TABLE CertificateData');
UPDATE CertificateData SET base64Cert=tmpbase64Cert;
ALTER TABLE CertificateData DROP COLUMN tmpbase64Cert;
CALL SYSPROC.ADMIN_CMD('REORG TABLE CertificateData');

--  KeyRecoveryData.keyData is currently VARCHAR(8000), but is defined as CLOB on other databases
ALTER TABLE KeyRecoveryData ADD tmpkeyData CLOB DEFAULT NULL;
UPDATE KeyRecoveryData SET tmpkeyData=keyData;
ALTER TABLE KeyRecoveryData DROP COLUMN keyData;
ALTER TABLE KeyRecoveryData ADD keyData CLOB DEFAULT NULL;
CALL SYSPROC.ADMIN_CMD('REORG TABLE KeyRecoveryData');
UPDATE KeyRecoveryData SET keyData=tmpkeyData;
ALTER TABLE KeyRecoveryData DROP COLUMN tmpkeyData;
CALL SYSPROC.ADMIN_CMD('REORG TABLE KeyRecoveryData');


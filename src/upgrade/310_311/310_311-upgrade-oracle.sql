
-- Perform data-type changes to have size consistency over all databases
--  ApprovalData.approvaldata is currently VARCHAR2(4000), but is defined as CLOB on other databases
ALTER TABLE ApprovalData ADD tmpapprovaldata CLOB DEFAULT NULL;
UPDATE ApprovalData SET tmpapprovaldata=approvaldata;
ALTER TABLE ApprovalData DROP COLUMN approvaldata;
ALTER TABLE ApprovalData ADD approvaldata CLOB DEFAULT NULL;
UPDATE ApprovalData SET approvaldata=tmpapprovaldata;
ALTER TABLE ApprovalData DROP COLUMN tmpapprovaldata;

-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD nextRunTimeStamp NUMBER(19) NOT NULL DEFAULT 0;
ALTER TABLE ServiceData ADD runTimeStamp NUMBER(19) NOT NULL DEFAULT 0;

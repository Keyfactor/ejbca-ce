-- This file should not be available in EJBCA 4.0 and all these changes should already have been made to EJBCA 3.11.0.


-- BOOLEANs on WebSphere were created as INT2 instead of "BOOLEAN". Hibernate will map this as BOOLEAN so we probably need to update this. 
--  We cannot cast INT2 to BOOLEAN so we have to work around it..
-- NOTE! This is only for WebSphere, not other application servers.
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

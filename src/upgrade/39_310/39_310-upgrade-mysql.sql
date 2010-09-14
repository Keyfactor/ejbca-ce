-- This file should not be available in EJBCA 4.0 and this is only a temporary fix

-- Handled automatically in part by Hibernate: ALTER TABLE LogEntryData CHANGE COLUMN comment logComment VARCHAR(250);
-- We still need to perform some magic..
UPDATE LogEntryData SET logComment=comment where logComment=NULL;
ALTER TABLE LogEntryData DROP COLUMN comment;
-- ..to keep old comments
ALTER TABLE TableProtectData DROP COLUMN keyRef;
-- Handled automatically by Hibernate: ALTER TABLE CertificateData ADD subjectKeyId VARCHAR(250) BINARY DEFAULT NULL;
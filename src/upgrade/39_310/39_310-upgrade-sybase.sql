ALTER TABLE LogEntryData RENAME comment TO logComment;
ALTER TABLE TableProtectData DROP COLUMN keyRef;
ALTER TABLE CertificateData ADD subjectKeyId VARCHAR(255) DEFAULT NULL;

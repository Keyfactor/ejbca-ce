RENAME COLUMN LogEntryData.comment TO logComment;
ALTER TABLE TableProtectData DROP COLUMN keyRef;
ALTER TABLE CertificateData ADD subjectKeyId VARCHAR(255,0) DEFAULT NULL;

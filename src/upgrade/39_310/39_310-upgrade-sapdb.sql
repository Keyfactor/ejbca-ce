RENAME COLUMN LogEntryData.comment TO logComment;
ALTER TABLE TableProtectData DROP COLUMN keyRef;
ALTER TABLE CertificateData ADD subjectKeyId VARCHAR(256) DEFAULT NULL;

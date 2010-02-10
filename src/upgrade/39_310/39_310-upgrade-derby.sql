RENAME COLUMN LogEntryData.comment TO logComment;
ALTER TABLE TableProtectData DROP COLUMN keyRef;
ALTER TABLE CertificateData ADD COLUMN subjectKeyId VARCHAR(256) WITH DEFAULT NULL;

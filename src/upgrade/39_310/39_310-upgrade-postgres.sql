ALTER TABLE LogEntryData RENAME COLUMN comment TO logComment;
ALTER TABLE TableProtectData DROP COLUMN keyRef;
ALTER TABLE CertificateData ADD subjectKeyId TEXT DEFAULT NULL;

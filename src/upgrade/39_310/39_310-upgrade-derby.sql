-- If you are using an older version of Derby, such as 10.2, you need to drop and re-create this table. See doc/howto/create-tables-ejbca3-derby.sql for drop/create statements.
-- this is because Derby 10.2 does not support rename column or drop column
RENAME COLUMN LogEntryData.comment TO logComment;
-- If you are using an older version of Derby, such as 10.2, you need to drop and re-create this table. See doc/howto/create-tables-ejbca3-derby.sql for drop/create statements.
ALTER TABLE TableProtectData DROP COLUMN keyRef;
ALTER TABLE CertificateData ADD COLUMN subjectKeyId VARCHAR(256) WITH DEFAULT NULL;

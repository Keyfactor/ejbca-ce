EXEC sp_rename 'LogEntryData.[comment]', 'logComment', 'COLUMN';
ALTER TABLE TableProtectData DROP COLUMN keyRef;

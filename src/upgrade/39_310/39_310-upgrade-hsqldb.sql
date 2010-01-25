ALTER TABLE LogEntryData ALTER COLUMN comment RENAME TO logComment;
ALTER TABLE TableProtectData DROP COLUMN keyRef;

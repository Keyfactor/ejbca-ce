ALTER TABLE LogEntryData CHANGE COLUMN comment logComment VARCHAR(250);
ALTER TABLE TableProtectData DROP COLUMN keyRef;

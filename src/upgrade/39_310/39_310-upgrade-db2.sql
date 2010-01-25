ALTER TABLE LogEntryData ADD COLUMN logComment varchar(254);
UPDATE LogEntryData SET logComment = comment;
ALTER TABLE LogEntryData DROP COLUMN comment;
CALL SYSPROC.ADMIN_CMD('REORG TABLE LogEntryData');
ALTER TABLE TableProtectData DROP COLUMN keyRef;
CALL SYSPROC.ADMIN_CMD('REORG TABLE TableProtectData');

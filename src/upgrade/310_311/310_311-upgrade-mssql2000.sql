
-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD nextRunTimeStamp BIGINT NOT NULL DEFAULT '0';
ALTER TABLE ServiceData ADD runTimeStamp BIGINT NOT NULL DEFAULT '0';

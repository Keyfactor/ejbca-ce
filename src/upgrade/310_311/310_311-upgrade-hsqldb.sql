
-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD nextRunTimeStamp BIGINT DEFAULT 0 NOT NULL;
ALTER TABLE ServiceData ADD runTimeStamp BIGINT DEFAULT 0 NOT NULL;

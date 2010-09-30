-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD nextRunTimeStamp NUMERIC(38,0) DEFAULT 0 NOT NULL;
ALTER TABLE ServiceData ADD runTimeStamp NUMERIC(38,0) DEFAULT 0 NOT NULL;

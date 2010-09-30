
-- AdminGroupData.pK was named "primkey" on JBoss because of an empty mapping file in EJBCA 3.x.
ALTER TABLE AdminGroupData DROP CONSTRAINT pk_admingroupdata RESTRICT;
ALTER TABLE AdminGroupData RENAME COLUMN primkey TO pK;
ALTER TABLE AdminGroupData ADD CONSTRAINT pk_admingroupdata PRIMARY KEY (pK);

-- ServiceData gets two new columns
ALTER TABLE ServiceData ADD COLUMN nextRunTimeStamp INT8 NOT NULL WITH DEFAULT;
ALTER TABLE ServiceData ADD COLUMN runTimeStamp INT8 NOT NULL WITH DEFAULT;

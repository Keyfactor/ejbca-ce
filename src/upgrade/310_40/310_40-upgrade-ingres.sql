-- This file should not be available in EJBCA 4.0 and all these changes should already have been made to EJBCA 3.11.0.


-- AdminGroupData.pK was named "primkey" on JBoss because of an empty mapping file in EJBCA 3.x.
ALTER TABLE AdminGroupData DROP CONSTRAINT pk_admingroupdata RESTRICT;
ALTER TABLE AdminGroupData RENAME COLUMN primkey TO pK;
ALTER TABLE AdminGroupData ADD CONSTRAINT pk_admingroupdata PRIMARY KEY (pK);

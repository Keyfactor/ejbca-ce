-- version: $Id$

-- There is normally no use for the primary key
ALTER TABLE AuditRecordData DROP PRIMARY KEY;
-- Partitioning to allow easy reclaim of space after export and delete of old audit log.
-- If you never plan on removing Security Events Audit log, this can be skipped.
-- This example will divide the stored data by for a few nodes with up to 250M rows in
-- in each partition.
-- ALTER TABLE AuditRecordData REMOVE PARTITIONING;
-- ALTER TABLE AuditRecordData PARTITION BY RANGE( sequenceNumber ) SUBPARTITION BY KEY( nodeId ) (
--   PARTITION p01 VALUES LESS THAN (250000000) (
--     SUBPARTITION s01a, SUBPARTITION s01b,
--     SUBPARTITION s01c, SUBPARTITION s01d ),
--   PARTITION p02 VALUES LESS THAN (500000000) (
--     SUBPARTITION s02a, SUBPARTITION s02b,
--     SUBPARTITION s02c, SUBPARTITION s02d ),
--   PARTITION p03 VALUES LESS THAN (750000000) (
--    SUBPARTITION s03a, SUBPARTITION s03b,
--     SUBPARTITION s03c, SUBPARTITION s03d ),
--   PARTITION p05 VALUES LESS THAN MAXVALUE (
--     SUBPARTITION s04a, SUBPARTITION s04b,
--     SUBPARTITION s04c, SUBPARTITION s04d )
-- );

-- Partition pruning to increase speed of finding CA certificates instead of
-- having a largely unused index.
ALTER TABLE CertificateData DROP INDEX certificatedata_idx5;
-- If we created certificatedata_idx12 with the UNIQUE keyword we need to rebuild it.
-- Note: This partitioning will only gurantee uniqueness of "serialNumber, issuerDN" and
-- "fingerprint" within each "type".
ALTER TABLE CertificateData DROP INDEX certificatedata_idx12;
ALTER TABLE CertificateData ADD UNIQUE INDEX certificatedata_idx12 (serialNumber, issuerDN, type);
ALTER TABLE CertificateData REMOVE PARTITIONING;
ALTER TABLE CertificateData DROP PRIMARY KEY;
ALTER TABLE CertificateData ADD UNIQUE INDEX certificatedata_idx13 (fingerprint, type);
ALTER TABLE CertificateData PARTITION BY LIST(type) (
  PARTITION pCa VALUES IN (2,8),
  PARTITION pOther VALUES IN (0,1,16)
);

-- Compression of large tables to increase relative in-memory caching
ALTER TABLE AuditRecordData row_format=compressed key_block_size=4;
ALTER TABLE CertReqHistoryData row_format=compressed key_block_size=4;
ALTER TABLE CRLData row_format=compressed key_block_size=16;
ALTER TABLE CertificateData row_format=compressed key_block_size=8;
ALTER TABLE UserData row_format=compressed key_block_size=4;

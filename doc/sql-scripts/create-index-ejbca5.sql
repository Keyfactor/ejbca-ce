-- version: $Id$

-- Note: For MySQL's NDB engine add 'USING HASH' to all UNIQUE indexes.

-- Selecting log entries when verifying/exporting IntegrityProtectedDevice logs:
ALTER TABLE AuditRecordData ADD UNIQUE INDEX auditrecorddata_idx2 (nodeId,sequenceNumber);
-- Selecting log entries from IntegrityProtectedDevice logs in the AdminGUI is usually
-- done using time constraints.
ALTER TABLE AuditRecordData ADD INDEX auditrecorddata_idx3 (timeStamp);

-- unique to ensure that no two CRLs with the same CRLnumber from the same issuer is created
ALTER TABLE CRLData ADD UNIQUE INDEX crldata_idx3 (cRLNumber, issuerDN);

-- With a large database at least idx12 and idx5 are needed during startup of EJBCA.
ALTER TABLE CertificateData ADD INDEX certificatedata_idx2 (username);
ALTER TABLE CertificateData ADD INDEX certificatedata_idx4 (subjectDN);
ALTER TABLE CertificateData ADD INDEX certificatedata_idx5 (type);
ALTER TABLE CertificateData ADD INDEX certificatedata_idx11 (subjectKeyId);
-- UNIQUE increases certainty the no two certificate with the same issuer and serial number can be issued
-- this index can not be unique when CVC CAs are used, because CV Certificates don't have serial numbers so all is 0
-- if no unique index is present, the uniqueness will be enforced using queries before issuance
-- To enable custom certificate serialNumbers in EJBCA we insert test data to see if certificatedata_idx12 is unique.
-- We need to remove these rows before proceeding or the index creation will fail.
DELETE FROM CertificateData WHERE fingerprint='caba75f68c833c3c2d33f3f5052b7d5a76e80383';
DELETE FROM CertificateData WHERE fingerprint='05a219d835622653192c30eeeee8f01f918b30fb';
ALTER TABLE CertificateData ADD UNIQUE INDEX certificatedata_idx12 (serialNumber, issuerDN);
--ALTER TABLE CertificateData ADD INDEX certificatedata_idx12 (serialNumber, issuerDN);

ALTER TABLE CertReqHistoryData ADD INDEX historydata_idx1 (username);
ALTER TABLE CertReqHistoryData ADD INDEX historydata_idx3 (serialNumber);

ALTER TABLE UserData ADD INDEX userdata_idx10 (subjectDN);
-- Increase lookup speed of a small subset of users with a specific status
ALTER TABLE UserData ADD INDEX userdata_idx11 (status);

ALTER TABLE PublisherQueueData ADD INDEX publisherqueue_idx3 (publisherId, publishStatus, timeCreated);

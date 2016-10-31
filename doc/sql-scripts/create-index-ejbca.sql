-- version: $Id$

-- Note: For MySQL's NDB engine add 'USING HASH' to all UNIQUE indexes.

-- Selecting log entries when verifying/exporting IntegrityProtectedDevice logs:
CREATE UNIQUE INDEX auditrecorddata_idx2 ON AuditRecordData (nodeId,sequenceNumber);
-- Selecting log entries from IntegrityProtectedDevice logs in the AdminGUI is usually
-- done using time constraints.
CREATE INDEX auditrecorddata_idx3 ON AuditRecordData (timeStamp);

-- unique to ensure that no two CRLs with the same CRLnumber from the same issuer is created
CREATE UNIQUE INDEX crldata_idx3 ON CRLData (cRLNumber, issuerDN);
-- Index to ensure CRL generation is not slowed down when looking for the next CRL Number, even of you have hundreds of thounsand of old CRL in the DB
CREATE INDEX crldata_idx4 ON CRLData (issuerDN,deltaCRLIndicator,crlNumber);

-- unique to ensure that no two CAs with the same name is created, since EJBCA code assumes that name is unique
CREATE UNIQUE INDEX cadata_idx1 ON CAData (name);

-- With a large database at least idx12 and idx5 are needed during startup of EJBCA.
-- For an OCSP responder idx4 (loading signer certificate chain and request signer CA certificates), idx5 (loading CA certificates) and idx12 (status lookups) should be enough.
CREATE INDEX certificatedata_idx2 ON CertificateData (username);
CREATE INDEX certificatedata_idx4 ON CertificateData (subjectDN);
CREATE INDEX certificatedata_idx5 ON CertificateData (type);
CREATE INDEX certificatedata_idx6 ON CertificateData (issuerDN,status);
CREATE INDEX certificatedata_idx7 ON CertificateData(certificateProfileId);
-- The following index is currently needed for finding expired/expiring certificates
-- CREATE INDEX certificatedata_idx8 ON CertificateData(expireDate, status);
CREATE INDEX certificatedata_idx11 ON CertificateData (subjectKeyId);
-- UNIQUE increases certainty the no two certificate with the same issuer and serial number can be issued
-- this index can not be unique when CVC CAs are used, because CV Certificates don't have serial numbers so all is 0
-- if no unique index is present, the uniqueness will be enforced using queries before issuance
-- To enable custom certificate serialNumbers in EJBCA we insert test data to see if certificatedata_idx12 is unique.
-- We need to remove these rows before proceeding or the index creation will fail.
DELETE FROM CertificateData WHERE fingerprint='caba75f68c833c3c2d33f3f5052b7d5a76e80383';
DELETE FROM CertificateData WHERE fingerprint='05a219d835622653192c30eeeee8f01f918b30fb';
CREATE UNIQUE INDEX certificatedata_idx12 ON CertificateData (serialNumber, issuerDN);
-- If using CVC CA remove the above UNIQUE index, and apply the below NON UNIQUE index instead
-- Do not apply both of them!
-- CREATE INDEX certificatedata_idx12 ON CertificateData (serialNumber, issuerDN);

CREATE INDEX historydata_idx1 ON CertReqHistoryData (username);
CREATE INDEX historydata_idx3 ON CertReqHistoryData (serialNumber);

CREATE INDEX userdata_idx10 ON UserData (subjectDN);
-- Increase lookup speed of a small subset of users with a specific status
CREATE INDEX userdata_idx11 ON UserData (status);

CREATE INDEX publisherqueue_idx3 ON PublisherQueueData (publisherId, publishStatus, timeCreated);

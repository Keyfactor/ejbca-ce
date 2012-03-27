-- version: $Id$

ALTER TABLE AuditRecordData DROP INDEX auditrecorddata_idx2;
ALTER TABLE AuditRecordData DROP INDEX auditrecorddata_idx3;
ALTER TABLE CRLData DROP INDEX crldata_idx3;

ALTER TABLE CertificateData DROP INDEX certificatedata_idx2;
ALTER TABLE CertificateData DROP INDEX certificatedata_idx4;
ALTER TABLE CertificateData DROP INDEX certificatedata_idx5;
ALTER TABLE CertificateData DROP INDEX certificatedata_idx11;
ALTER TABLE CertificateData DROP INDEX certificatedata_idx12;
-- Only added when MySQL partition pruning is used:
-- ALTER TABLE CertificateData DROP INDEX certificatedata_idx13;
-- ALTER TABLE CertificateData DROP INDEX certificatedata_idx14;

ALTER TABLE CertReqHistoryData DROP INDEX historydata_idx1;
ALTER TABLE CertReqHistoryData DROP INDEX historydata_idx1;

ALTER TABLE CertReqHistoryData ADD INDEX historydata_idx1 (username);
ALTER TABLE CertReqHistoryData ADD INDEX historydata_idx3 (serialNumber);

ALTER TABLE UserData DROP INDEX userdata_idx10;
ALTER TABLE UserData DROP INDEX userdata_idx11;

ALTER TABLE PublisherQueueData DROP INDEX publisherqueue_idx3;

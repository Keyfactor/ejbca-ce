-- version: $Id$

-- Note: For MySQL's NDB engine add 'USING HASH' to all UNIQUE indexes.

-- Selecting log entries when verifying/exporting IntegrityProtectedDevice logs:
CREATE UNIQUE INDEX auditrecorddata_idx2 ON AuditRecordData (nodeId,sequenceNumber);
-- Selecting log entries from IntegrityProtectedDevice logs in the AdminGUI is usually
-- done using time constraints.
CREATE INDEX auditrecorddata_idx3 ON AuditRecordData (timeStamp);
CREATE INDEX auditrecorddata_idx4 ON AuditRecordData (searchDetail2);

-- Index to ensure CRL generation is not slowed down when looking for the next CRL Number, even of you have hundreds of thousands of old CRLs in the DB
CREATE INDEX crldata_idx5 ON CRLData(cRLNumber, issuerDN, crlPartitionIndex);
CREATE UNIQUE INDEX crldata_idx6 ON CRLData(issuerDN, crlPartitionIndex, deltaCRLIndicator, cRLNumber);
-- Drop old indexes on CRLData used on installations without partitioned CRLs before EJBCA 7.4
-- run these two DROP INDEX commands manually if you installed an earlier version of indexes, and want to start using partitioned CRLs
-- drop index syntax is different for different databases, for example on PostgreSQL you should remove the ON keyword
-- modify the statements to be compatible with yor database
-- DROP INDEX IF EXISTS crldata_idx3 ON CRLData;
-- DROP INDEX IF EXISTS crldata_idx4 ON CRLData;

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
DELETE FROM Base64CertData WHERE fingerprint='caba75f68c833c3c2d33f3f5052b7d5a76e80383';
DELETE FROM Base64CertData WHERE fingerprint='05a219d835622653192c30eeeee8f01f918b30fb';
CREATE UNIQUE INDEX certificatedata_idx12 ON CertificateData (serialNumber, issuerDN);
-- If using CVC CA remove the above UNIQUE index, and apply the below NON UNIQUE index instead
-- Do not apply both of them!
-- CREATE INDEX certificatedata_idx12 ON CertificateData (serialNumber, issuerDN);
-- The following indexes have been identified to be beneficial to performance in the following scenario:
-- Keyfactor Gateway Connector for Keyfactor Remote trying to query/page through 1.5 mill certs with the REST Api on a Hardware Appliance (even 2020XL)
CREATE INDEX certificatedata_idx15 ON CertificateData (issuerDN,notBefore);
CREATE INDEX certificatedata_idx16 ON CertificateData (issuerDN,revocationDate);
-- Index for base CRL generation
CREATE INDEX certificatedata_idx17 ON CertificateData (issuerDN, status, crlPartitionIndex);
-- Index for delta CRL generation
CREATE INDEX certificatedata_idx18 ON CertificateData (issuerDN, status, crlPartitionIndex, revocationDate);
-- Optimized index for CRL generation on Microsoft SQL Server (should be used instead of certificatedata_idx17 and certificatedata_idx18).
-- CREATE NONCLUSTERED INDEX certificatedata_idx19 ON CertificateData (issuerDN, status, revocationDate, fingerprint, crlPartitionIndex) INCLUDE (expireDate, revocationReason, serialNumber);
-- Index useful when searching for certificates with an invalidity date.
-- CREATE INDEX certificatedata_idx20 ON CertificateData (iivalidityDate);  

CREATE INDEX historydata_idx1 ON CertReqHistoryData (username);
CREATE INDEX historydata_idx3 ON CertReqHistoryData (serialNumber);

CREATE INDEX userdata_idx10 ON UserData (subjectDN);
-- Increase lookup speed of a small subset of users with a specific status
CREATE INDEX userdata_idx11 ON UserData (status);

CREATE INDEX publisherqueue_idx3 ON PublisherQueueData (publisherId, publishStatus, timeCreated);

-- When using a role members with many entries
CREATE INDEX rolemember_idx1 ON RoleMemberData (tokenType,roleId);

-- When using a blocklist with many entries
CREATE INDEX blocklist_idx1 ON BlacklistData (type,value);

-- Indexes for NoConflictCertificateData (we don't need username, subjectDN, type, subjectKeyId indexes for revoked throw away certificates)
CREATE INDEX noconflictcertificatedata_idx1 ON NoConflictCertificateData (serialNumber, issuerDN);
CREATE INDEX noconflictcertificatedata_idx2 ON NoConflictCertificateData (fingerprint);
CREATE INDEX noconflictcertificatedata_idx3 ON NoConflictCertificateData (issuerDN,status);
CREATE INDEX noconflictcertificatedata_idx4 ON NoConflictCertificateData (certificateProfileId);
-- Index for base CRL generation
CREATE INDEX noconflictcertificatedata_idx5 ON NoConflictCertificateData (issuerDN, status, crlPartitionIndex);
-- Index for delta CRL generation
CREATE INDEX noconflictcertificatedata_idx6 ON NoConflictCertificateData (issuerDN, status, crlPartitionIndex, revocationDate);
-- Optimized index for CRL generation on Microsoft SQL Server (should be used instead of noconflictcertificatedata_idx5 and noconflictcertificatedata_idx6).
-- CREATE NONCLUSTERED INDEX noconflictcertificatedata_idx7 ON NoConflictCertificateData (issuerDN, status, revocationDate, fingerprint, crlPartitionIndex) INCLUDE (expireDate, revocationReason, serialNumber);

-- Index for searching for ACME accounts by public key
CREATE INDEX acmeaccountdata_idx1 ON AcmeAccountData (currentKeyId);

-- Index for searching for ACME orders by account id
CREATE INDEX acmeorderdata_idx1 ON AcmeOrderData (accountId);

-- Index for searching for ACME orders by fingerprint and status
CREATE INDEX acmeorderdata_idx2 ON AcmeOrderData (fingerprint, status);

-- Index for searching for ACME authorizations by account id
CREATE INDEX acmeauthorizationdata_idx1 ON AcmeAuthorizationData (orderId,accountId,expires,status);

-- Index for searching for ACME authorizations by order id
CREATE INDEX acmeauthorizationdata_idx2 ON AcmeAuthorizationData (orderId);

-- Index for searching for ACME challenges by authorization id
CREATE INDEX acmechallengedata_idx1 ON AcmeChallengeData (authorizationId);

-- Index for searching for Signed Certificate Timestamps by fingerprint
CREATE INDEX sctdata_idx1 ON SctData (fingerprint);

-- Indexes for searching for OCSP responses by cAId, serialNumber or nextUpdate.
CREATE INDEX ocspresponsedata_idx1 ON OcspResponseData (cAId);
CREATE INDEX ocspresponsedata_idx2 ON OcspResponseData (serialNumber);
CREATE INDEX ocspresponsedata_idx3 ON OcspResponseData (producedAt);


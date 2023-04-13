-- version: $Id$

DROP INDEX auditrecorddata_idx2 ON AuditRecordData;
DROP INDEX auditrecorddata_idx3 ON AuditRecordData;

DROP INDEX crldata_idx3 ON CRLData;

DROP INDEX cadata_idx1 ON CAData;

DROP INDEX certificatedata_idx2 ON CertificateData;
DROP INDEX certificatedata_idx4 ON CertificateData;
DROP INDEX certificatedata_idx5 ON CertificateData;
DROP INDEX certificatedata_idx6 ON CertificateData;
DROP INDEX certificatedata_idx7 ON CertificateData;
-- DROP INDEX certificatedata_idx8 ON CertificateData;
DROP INDEX certificatedata_idx11 ON CertificateData;
DROP INDEX certificatedata_idx12 ON CertificateData;
-- Only added when MySQL partition pruning is used:
-- ALTER TABLE CertificateData DROP INDEX certificatedata_idx13;
-- ALTER TABLE CertificateData DROP INDEX certificatedata_idx14;
DROP INDEX certificatedata_idx15 ON CertificateData;
DROP INDEX certificatedata_idx16 ON CertificateData;
DROP INDEX certificatedata_idx17 ON CertificateData;
DROP INDEX certificatedata_idx18 ON CertificateData;
DROP INDEX certificatedata_idx19 ON CertificateData;
DROP INDEX certificatedata_idx20 ON CertificateData;

DROP INDEX historydata_idx1 ON CertReqHistoryData;
DROP INDEX historydata_idx3 ON CertReqHistoryData;

DROP INDEX userdata_idx10 ON UserData;
DROP INDEX userdata_idx11 ON UserData;

DROP INDEX publisherqueue_idx3 ON PublisherQueueData;

DROP INDEX rolemember_idx1 ON RoleMemberData;

DROP INDEX blocklist_idx1 ON BlacklistData;
-- If the index was created on an older version than EJBCA 7.5.0 then it should have the outmoded name. In that case use the line below instead.
-- DROP INDEX blacklist_idx1 ON BlacklistData;

DROP INDEX noconflictcertificatedata_idx1 ON NoConflictCertificateData;
DROP INDEX noconflictcertificatedata_idx2 ON NoConflictCertificateData;
DROP INDEX noconflictcertificatedata_idx3 ON NoConflictCertificateData;
DROP INDEX noconflictcertificatedata_idx4 ON NoConflictCertificateData;
DROP INDEX noconflictcertificatedata_idx5 ON NoConflictCertificateData;
DROP INDEX noconflictcertificatedata_idx6 ON NoConflictCertificateData;
DROP INDEX noconflictcertificatedata_idx7 ON NoConflictCertificateData;

DROP INDEX acmeaccountdata_idx1 ON AcmeAccountData;
DROP INDEX acmeorderdata_idx1 ON AcmeOrderData;
DROP INDEX acmeorderdata_idx2 ON AcmeOrderData;
DROP INDEX acmeauthorizationdata_idx1 ON AcmeAuthorizationData;
DROP INDEX acmeauthorizationdata_idx2 ON AcmeAuthorizationData;

DROP INDEX acmechallengedata_idx1 ON AcmeChallengeData;

DROP INDEX ocspresponsedata_idx1 ON OcspResponseData;
DROP INDEX ocspresponsedata_idx2 ON OcspResponseData;
DROP INDEX ocspresponsedata_idx3 ON OcspResponseData;

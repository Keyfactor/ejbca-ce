-- Note!
-- If using UTF-8 character encoding in MySQL index length is limited to 1000 bytes, and UTF-8 characters take up 3 bytes.
-- Some index rown needs to be changed because of this like:
-- For MySQL NDB 'using hash' should be added to all unique indexes.

-- To enable custom certificate serialNumbers in EJBCA we insert test data to see if certificatedata_idx1 is enabled.
-- We need to remove these rows before proceeding or the index creation will fail.
delete from CertificateData where fingerprint='caba75f68c833c3c2d33f3f5052b7d5a76e80383';
delete from CertificateData where fingerprint='05a219d835622653192c30eeeee8f01f918b30fb';
 
-- Selecting log entries when verifying/exporting IntegrityProtectedDevice logs:
create unique index auditrecorddata_idx1 on AuditRecordData (nodeId,timeStamp,sequenceNumber);

-- Indexes on CRLData:	
-- unique to ensure that no two CRLs with the same CRLnumber from the same issuer is created
create unique index crldata_idx1 on CRLData (issuerDN,cRLNumber);
create index crldata_idx2 on CRLData (issuerDN,deltaCRLIndicator);
-- On EJBCA 3.5: create index crldata_idx2 on CRLData (issuerDN);

-- Indexes on CertificateData:
-- With a large database at least idx1 and idx5 are needed during startup of EJBCA.
-- unique to increase security the no two certificate with the same issuer and serial number can be issued
-- this index can not be unique when CVC CAs are used, because CV Certificates don't have serial numbers so all is 0
create unique index certificatedata_idx1 on CertificateData (issuerDN,serialNumber);
create index certificatedata_idx2 on CertificateData (username);
create index certificatedata_idx3 on CertificateData (status,issuerDN);
create index certificatedata_idx4 ON CertificateData(subjectDN); 
create index certificatedata_idx5 ON CertificateData(type);
create index certificatedata_idx6 ON CertificateData(serialNumber);
create index certificatedata_idx7 on CertificateData(certificateProfileId);
create index certificatedata_idx8 on CertificateData(expireDate, status);
create index certificatedata_idx9 on CertificateData(subjectKeyId,issuerDN);
create index certificatedata_idx10 on CertificateData(subjectDN,issuerDN);

-- Indexes on UserData:
create index userdata_idx1 on UserData (cAId,endEntityProfileId);
create index userdata_idx2 on UserData (cAId,timeCreated);
create index userdata_idx3 on UserData (cAId,timeModified);
-- Don't need this because cAId is included in other indexes
-- create index userdata_idx4 on UserData (cAId);
-- This is already the primary key.. we don't need to index it.. create index userdata_idx5 on UserData (username);
create index userdata_idx6 on UserData (username, cAId);
create index userdata_idx7 on UserData (status, cAId);
create index userdata_idx8 on UserData (subjectDN, cAId);
create index userdata_idx9 on UserData (certificateProfileId);

-- Indexes on CertReqHistoryData: for viewing history
create index historydata_idx1 on CertReqHistoryData (username);
create unique index historydata_idx2 on CertReqHistoryData (issuerDN,serialNumber);

-- Indexes on CAData
-- CAData is usually very small, but lets make good indexes overall
create index cadata_idx1 on CAData (name);

-- Indexes on AccessRulesData
create index accessrules_idx1 on AccessRulesData (AdminGroupData_accessRules);

-- Indexes on AdminEntityData
create index adminentity_idx1 on AdminEntityData (AdminGroupData_adminEntities);

-- Indexes on PublisherQueueData
create index publisherqueue_idx1 on PublisherQueueData (publisherId, publishStatus);
create index publisherqueue_idx2 on PublisherQueueData (fingerprint);
create index publisherqueue_idx3 on PublisherQueueData (publisherId, publishStatus, timeCreated);

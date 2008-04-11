-- Selecting log entries when viewing logs:
create index logentry_idx1 on LogEntryData (time);
create index logentry_idx2 on LogEntryData (caId);
create index logentry_idx3 on LogEntryData (event);
create index logentry_idx4 on LogEntryData (username);

-- Indexes on CRLData:	
-- unique to ensure that no two CRLs with the same CRLnumber from the same issuer is created
create unique index crldata_idx1 on CRLData (issuerDN,cRLNumber);
create index crldata_idx2 on CRLData (issuerDN,deltaCRLIndicator);
-- On EJBCA 3.5: create index crldata_idx2 on CRLData (issuerDN);

-- Indexes on CertificateData:
-- unique to increase security the no two certificate with the same issuer and serial number can be issued
create unique index certificatedata_idx1 on CertificateData (issuerDN,serialNumber);
create index certificatedata_idx2 on CertificateData (username);
create index certificatedata_idx3 on CertificateData (status,issuerDN);
create index certificatedata_idx4 ON CertificateData(subjectDN); 

-- Indexes on UserData:
create index userdata_idx1 on UserData (cAId,endEntityProfileId);
create index userdata_idx2 on UserData (cAId,timeCreated);
create index userdata_idx3 on UserData (cAId,timeModified);
create index userdata_idx4 on UserData (cAId);
create index userdata_idx5 on UserData (username);

-- Indexes on CertReqHistoryData: for viewing history
create index historydata_idx1 on CertReqHistoryData (username);
create index historydata_idx2 on CertReqHistoryData (issuerDN,serialNumber);

-- Indexes on TableProtectData: searches when verifying, usually this is disabled
create index protect_idx1 on TableProtectData (dbKey,dbType);

-- Indexes on ProtectedLogData;
-- ProtectedLogData does only exist in EJBCA 3.6 and later
create index protectedlogdata_idx1 on ProtectedLogData (nodeGUID, counter);
-- Oracle does not like the b64Protection(1) notification, use simply b64Protection instead
-- create index protectedlogdata_idx2 on ProtectedLogData (nodeGUID, eventTime, b64Protection);
create index protectedlogdata_idx2 on ProtectedLogData (nodeGUID, eventTime, b64Protection(1));
create index protectedlogdata_idx3 on ProtectedLogData (username, caId, module);
create index protectedlogexportdata_idx1 on ProtectedLogExportData (exportStartTime);

create index logentry_idx1 on LogEntryData (time);
create index logentry_idx2 on LogEntryData (caId);
create index logentry_idx3 on LogEntryData (event);
create index logentry_idx4 on LogEntryData (username);
create index crldata_idx1 on CRLData (issuerDN,cRLNumber);
create index certificatedata_idx1 on CertificateData (issuerDN,serialNumber);
create index certificatedata_idx2 on CertificateData (username);
create index certificatedata_idx3 on CertificateData (status,issuerDN);
create index certificatedata_idx4 ON CertificateData(subjectDN); 
create index userdata_idx1 on UserData (cAId,endEntityProfileId);
create index historydata_idx1 on CertReqHistoryData (username);
create index historydata_idx2 on CertReqHistoryData (issuerDN,serialNumber);
create index protect_idx1 on TableProtectData (dbKey,dbType);
create index protectedlogdata_idx1 on ProtectedLogData (nodeGUID, counter);
-- Oracle does not like the b64Protection(1) notification, use simply b64Protection instead
-- create index protectedlogdata_idx2 on ProtectedLogData (nodeGUID, eventTime, b64Protection);
create index protectedlogdata_idx2 on ProtectedLogData (nodeGUID, eventTime, b64Protection(1));
create index protectedlogdata_idx3 on ProtectedLogData (username, caId, module);
create index protectedlogexportdata_idx1 on ProtectedLogExportData (exportStartTime);

create index logentry_idx1 on LogEntryData (time);
create index logentry_idx2 on LogEntryData (caid);
create index logentry_idx3 on LogEntryData (event);
create index logentry_idx4 on LogEntryData (username);
create index crldata_idx1 on CRLData (issuerDN,cRLNumber);
create index certificatedata_idx1 on CertificateData (issuerDN,serialNumber);
create index certificatedata_idx2 on CertificateData (username);
create index certificatedata_idx3 on CertificateData (status,issuerDN);
create index userdata_idx1 on UserData (caid,endEntityprofileId);
create index historydata_idx1 on CertReqHistoryData (username);
create index protect_idx1 on TableProtectData (dbKey,dbType);


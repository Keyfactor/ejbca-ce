update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD tag TEXT DEFAULT NULL;
ALTER TABLE CertificateData ADD certificateProfileId INT4 DEFAULT 0;
ALTER TABLE CertificateData ADD updateTime INT8 NOT NULL DEFAULT 0;
UPDATE CertificateData SET certificateProfileId=0;
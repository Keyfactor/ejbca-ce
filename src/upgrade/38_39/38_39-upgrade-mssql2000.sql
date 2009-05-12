update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD tag VARCHAR(256) DEFAULT NULL;
ALTER TABLE CertificateData ADD certificateProfileId INTEGER DEFAULT 0;
ALTER TABLE CertificateData ADD updateTime DECIMAL(20) NOT NULL DEFAULT 0;
UPDATE CertificateData SET certificateProfileId=0;
ALTER TABLE CertificateData ADD tag VARCHAR(250) BINARY DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD certificateProfileId int(11) DEFAULT NULL;
UPDATE CertificateData, UserData SET CertificateData.certificateProfileId=UserData.certificateProfileId WHERE CertificateData.username=UserData.username;
ALTER TABLE CertificateData ADD updateTime bigint(20) NOT NULL DEFAULT 0;

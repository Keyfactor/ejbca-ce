ALTER TABLE CertificateData ADD tag VARCHAR(255) DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD certificateProfileId NUMBER(10) DEFAULT NULL;
UPDATE CertificateData, UserData SET CertificateData.certificateProfileId=UserData.certificateProfileId WHERE CertificateData.username=UserData.username;
ALTER TABLE CertificateData ADD updateTime NUMBER(19) NOT NULL DEFAULT 0;

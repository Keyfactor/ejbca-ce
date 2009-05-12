update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD tag VARCHAR(255) DEFAULT NULL;
ALTER TABLE CertificateData ADD certificateProfileId NUMBER(10) DEFAULT 0;
ALTER TABLE CertificateData ADD updateTime NUMBER(19) DEFAULT 0 NOT NULL;
UPDATE CertificateData SET certificateProfileId=0;

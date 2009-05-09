ALTER TABLE CertificateData ADD tag VARCHAR(255) DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD certificateProfileId NUMBER(10) DEFAULT 0;
update CertificateData c, UserData u set c.certificateProfileId=u.certificateProfileId where c.username=u.username;
ALTER TABLE CertificateData ADD updateTime NUMBER(19) DEFAULT 0 NOT NULL;

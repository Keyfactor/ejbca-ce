ALTER TABLE CertificateData ADD tag VARCHAR(255) DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD certificateProfileId INTEGER DEFAULT 0;
update CertificateData c, UserData u set c.certificateProfileId=u.certificateProfileId where c.username=u.username;
ALTER TABLE CertificateData ADD updateTime NUMERIC(38,0) DEFAULT 0 NOT NULL;

update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD tag VARCHAR(250) BINARY DEFAULT NULL;
ALTER TABLE CertificateData ADD certificateProfileId int(11) DEFAULT 0;
ALTER TABLE CertificateData ADD updateTime bigint(20) NOT NULL DEFAULT 0;
update CertificateData c, UserData u set c.certificateProfileId=u.certificateProfileId where c.username=u.username;

ALTER TABLE CertificateData ADD tag TEXT DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD certificateProfileId INT4 DEFAULT 0;
update CertificateData c, UserData u set c.certificateProfileId=u.certificateProfileId where c.username=u.username;
ALTER TABLE CertificateData ADD updateTime INT8 NOT NULL DEFAULT 0;

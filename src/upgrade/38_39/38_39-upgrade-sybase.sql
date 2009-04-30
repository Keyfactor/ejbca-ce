ALTER TABLE CertificateData ADD tag VARCHAR(255) DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;

ALTER TABLE CertificateData ADD tag VARCHAR(250) BINARY DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;

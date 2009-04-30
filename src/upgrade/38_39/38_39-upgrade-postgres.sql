ALTER TABLE CertificateData ADD tag TEXT SET DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;

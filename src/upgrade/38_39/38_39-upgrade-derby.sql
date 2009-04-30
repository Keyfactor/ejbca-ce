ALTER TABLE CertificateData ADD COLUMN tag VARCHAR(256) DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;

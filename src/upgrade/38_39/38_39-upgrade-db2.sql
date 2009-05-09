ALTER TABLE CertificateData ADD COLUMN tag VARCHAR(254) WITH DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD COLUMN certificateProfileId INTEGER WITH DEFAULT 0;
update CertificateData c, UserData u set c.certificateProfileId=u.certificateProfileId where c.username=u.username;
ALTER TABLE CertificateData ADD COLUMN updateTime BIGINT NOT NULL WITH DEFAULT 0;

ALTER TABLE CertificateData ADD COLUMN tag VARCHAR(256) WITH DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD COLUMN certificateProfileId INTEGER WITH DEFAULT 0;
UPDATE CertificateData SET certificateProfileId=(SELECT certificateProfileId FROM UserData WHERE CertificateData.username=UserData.username);
ALTER TABLE CertificateData ADD COLUMN updateTime BIGINT NOT NULL WITH DEFAULT 0;

ALTER TABLE CertificateData ADD COLUMN tag VARCHAR(256) DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD COLUMN certificateProfileId INTEGER DEFAULT NULL;
UPDATE CertificateData, UserData SET CertificateData.certificateProfileId=UserData.certificateProfileId WHERE CertificateData.username=UserData.username;
ALTER TABLE CertificateData ADD COLUMN updateTime BIGINT NOT NULL DEFAULT 0;

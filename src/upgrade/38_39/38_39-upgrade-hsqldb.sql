update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD COLUMN tag VARCHAR(256) DEFAULT NULL;
ALTER TABLE CertificateData ADD COLUMN certificateProfileId INTEGER DEFAULT 0;
ALTER TABLE CertificateData ADD COLUMN updateTime BIGINT DEFAULT 0 NOT NULL;
UPDATE CertificateData SET certificateProfileId=(SELECT certificateProfileId FROM UserData WHERE CertificateData.username=UserData.username);
UPDATE CertificateData SET certificateProfileId=0 where certificateProfileId is null; 
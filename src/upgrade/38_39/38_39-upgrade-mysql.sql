-- This file should not be available in EJBCA 4.0 and this is only a temporary fix

update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
-- Handled automatically by Hibernate: ALTER TABLE CertificateData ADD tag VARCHAR(250) BINARY DEFAULT NULL;
-- Handled automatically by Hibernate: ALTER TABLE CertificateData ADD certificateProfileId int(11) DEFAULT 0;
-- Handled automatically by Hibernate: ALTER TABLE CertificateData ADD updateTime bigint(20) NOT NULL DEFAULT 0;
UPDATE CertificateData SET certificateProfileId=0;
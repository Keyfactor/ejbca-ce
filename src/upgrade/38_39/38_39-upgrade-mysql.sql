ALTER TABLE CertificateData ADD tag VARCHAR(250) BINARY DEFAULT NULL;
update UserData set certificateProfileId=9 where username='tomcat' and certificateProfileId=1;
ALTER TABLE CertificateData ADD certificateProfileId int(11) DEFAULT 0;
UPDATE CertificateData SET certificateProfileId=(SELECT certificateProfileId FROM UserData WHERE CertificateData.username=UserData.username);
ALTER TABLE CertificateData ADD updateTime bigint(20) NOT NULL DEFAULT 0;

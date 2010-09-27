
-- The java.lang.Integer HardTokenProfileData.id was mapped as VARCHAR(80) BINARY in EJBCA 3.x.
ALTER TABLE HardTokenProfileData MODIFY id int(11) DEFAULT 0;

-- MySQL specific: CLOBs are mapped to "longtext" and not "text". According to http://opensource.atlassian.com/projects/hibernate/browse/HHH-2669 there is no performance gain from using "text".
-- These might be kind of optional.
ALTER TABLE CAData MODIFY data longtext DEFAULT NULL;
ALTER TABLE PublisherData MODIFY data longtext DEFAULT NULL;
ALTER TABLE PublisherQueueData MODIFY volatileData longtext DEFAULT NULL;
ALTER TABLE CertificateData MODIFY base64Cert longtext DEFAULT NULL;
ALTER TABLE KeyRecoveryData MODIFY keyData longtext DEFAULT NULL;
ALTER TABLE UserDataSourceData MODIFY data longtext DEFAULT NULL;
ALTER TABLE ServiceData MODIFY data longtext DEFAULT NULL;

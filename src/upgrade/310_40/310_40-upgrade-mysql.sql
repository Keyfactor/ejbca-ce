
-- The java.lang.Integer HardTokenProfileData.id was mapped as VARCHAR(80) BINARY in EJBCA 3.x.
ALTER TABLE HardTokenProfileData MODIFY id int(11) DEFAULT NULL;

-- MySQL specific: CLOBs are mapped to "longtext" and not "text". According to http://opensource.atlassian.com/projects/hibernate/browse/HHH-2669 there is no performance gain from using "text".
-- These might be kind of optional.. 
-- ALTER TABLE CAData MODIFY data longtext DEFAULT NULL;
-- ALTER TABLE PublisherData MODIFY data longtext DEFAULT NULL;
-- ALTER TABLE PublisherQueueData MODIFY volatileData longtext DEFAULT NULL;
-- ALTER TABLE CertificateData MODIFY base64Cert longtext DEFAULT NULL;
-- ALTER TABLE KeyRecoveryData MODIFY keyData longtext DEFAULT NULL;
-- ALTER TABLE ProtectedLogData MODIFY b64LinkedInEventIdentifiers longtext DEFAULT NULL;
-- ALTER TABLE ProtectedLogData MODIFY b64Protection longtext DEFAULT NULL;
-- ALTER TABLE ProtectedLogData MODIFY eventComment longtext DEFAULT NULL;
-- ALTER TABLE ProtectedLogExportData MODIFY b64Signature longtext DEFAULT NULL;
-- ALTER TABLE ProtectedLogExportData MODIFY b64SignatureCertificate longtext DEFAULT NULL;
-- ALTER TABLE ProtectedLogTokenData MODIFY b64TokenCertificate longtext DEFAULT NULL;
-- ALTER TABLE ProtectedLogTokenData MODIFY tokenReference longtext DEFAULT NULL;
-- ALTER TABLE UserDataSourceData MODIFY data longtext DEFAULT NULL;
-- ALTER TABLE ServiceData MODIFY data longtext DEFAULT NULL;

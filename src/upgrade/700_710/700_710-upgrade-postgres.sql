-- New columns in CertificateData are added by the JPA provider if there are sufficient privileges
-- if not added automatically the following SQL statements can be run to add the new columns 
-- ALTER TABLE CertificateData ADD crlPartitionIndex INT4;
-- ALTER TABLE NoConflictCertificateData ADD crlPartitionIndex INT4;
-- ALTER TABLE CRLData ADD crlPartitionIndex INT4;

-- DROP TABLE hardtokendata cascade;
-- DROP TABLE hardtokenissuerdata cascade;
-- DROP TABLE hardtokenprofiledata cascade;
-- DROP TABLE hardtokenpropertydata cascade;

-- New columns in CertificateData are added by the JPA provider if there are sufficient privileges
-- if not added automatically the following SQL statements can be run to add the new columns 
-- ALTER TABLE CertificateData ADD crlPartitionIndex INTEGER;
-- ALTER TABLE NoConflictCertificateData ADD crlPartitionIndex INTEGER;
-- ALTER TABLE CRLData ADD crlPartitionIndex INTEGER;

-- DROP TABLE hardtokendata if exists;
-- DROP TABLE hardtokenissuerdata if exists;
-- DROP TABLE hardtokenprofiledata if exists;
-- DROP TABLE hardtokenpropertydata if exists;

-- New columns in CertificateData are added by the JPA provider if there are sufficient privileges
-- if not added automatically the following SQL statements can be run to add the new columns 
-- ALTER TABLE CertificateData ADD crlPartitionIndex NUMBER(10);
-- ALTER TABLE NoConflictCertificateData ADD crlPartitionIndex NUMBER(10);
-- ALTER TABLE CRLData ADD crlPartitionIndex NUMBER(10);

-- DROP TABLE hardtokendata cascade constraints;
-- DROP TABLE hardtokenissuerdata cascade constraints;
-- DROP TABLE hardtokenprofiledata cascade constraints;
-- DROP TABLE hardtokenpropertydata cascade constraints;

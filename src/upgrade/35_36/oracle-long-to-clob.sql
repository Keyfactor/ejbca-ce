-- This script contains sql statements to change all columns of type LONG to CLOB for the Oracle db.
-- This change is desired because LONG is deprecated in Oracle.
-- Even if you don't change the column types, EJBCA will still work with the old LONG type, at least with JBoss.

alter table APPROVALDATA modify (requestData clob);
alter table CADATA modify (data clob);
alter table PUBLISHERDATA modify (data clob);
alter table CERTIFICATEDATA modify (base64Cert clob);
alter table CERTREQHISTORYDATA modify (userDataVO clob);
alter table CRLDATA modify (base64Crl clob);
alter table HARDTOKENPROFILEDATA modify (data clob);
alter table KEYRECOVERYDATA modify (keyData clob);
alter table USERDATASOURCEDATA modify (data clob);
alter table USERDATA modify (extendedInformationData clob);
alter table SERVICEDATA modify (data clob);

-- drop and recreate, or rebuild, all your indexes after making this alteration
-- If your database user is not called EJBCA, you have to alter the index names below.

alter index EJBCA.PK_APPROVALDATA rebuild;
alter index EJBCA.PK_CADATA rebuild;
alter index EJBCA.PK_PUBLISHERDATA rebuild;
alter index EJBCA.PK_CERTIFICATEDATA rebuild;
alter index EJBCA.PK_CERTREQHISTORYDATA rebuild;
alter index EJBCA.PK_CRLDATA rebuild;
alter index EJBCA.PK_HARDTOKENPROFILEDATA rebuild;
alter index EJBCA.PK_KEYRECOVERYDATA rebuild;
alter index EJBCA.PK_USERDATASOURCEDATA rebuild;
alter index EJBCA.PK_USERDATA rebuild;
alter index EJBCA.PK_SERVICEDATA rebuild;

-- add rebuilding of the indexes you have added below

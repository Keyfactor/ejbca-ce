ALTER TABLE accessrulesdata
    ADD column rule integer DEFAULT '0' NOT NULL AFTER accessRule,
    ADD column isRecursive bit DEFAULT '0' NOT NULL AFTER rule,
    DROP column resource,
    MODIFY column accessRule varchar(256) DEFAULT NULL,
    MODIFY column `AdminGroupData_accessRules` integer DEFAULT NULL;
#
#  Fieldformats of
#    accessrulesdata.accessRule changed from varbinary NULL DEFAULT NULL to varchar(256) NULL DEFAULT NULL.
#    accessrulesdata.AdminGroupData_accessRules changed from varchar(256) NULL DEFAULT NULL to integer NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

ALTER TABLE adminentitydata
    MODIFY column matchWith integer DEFAULT '0' NOT NULL,
    MODIFY column matchType integer DEFAULT '0' NOT NULL,
    MODIFY column `AdminGroupData_adminEntities` integer NULL DEFAULT NULL;
#
#  Fieldformats of
#    adminentitydata.matchWith changed from integer NULL DEFAULT NULL to integer NOT NULL DEFAULT '0'.
#    adminentitydata.matchType changed from integer NULL DEFAULT NULL to integer NOT NULL DEFAULT '0'.
#    adminentitydata.AdminGroupData_adminEntities changed from varchar(256) NULL DEFAULT NULL to integer NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

ALTER TABLE admingroupdata
    ADD column pK integer DEFAULT '0' NOT NULL FIRST,
    ADD column cAId integer DEFAULT '0' NOT NULL AFTER adminGroupName,
    MODIFY column adminGroupName varchar(256) DEFAULT NULL,
    DROP column PRIMARY KEY,
    ADD column PRIMARY KEY (pK);
#
#  Fieldformat of
#    admingroupdata.adminGroupName changed from varchar(256) NOT NULL DEFAULT '' to varchar(256) NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

DROP TABLE availableaccessrulesdata;

ALTER TABLE hardtokendata
    ADD column significantIssuerDN varchar(256) DEFAULT NULL AFTER tokenType;

ALTER TABLE hardtokenissuerdata
    ADD column adminGroupId integer DEFAULT '0' NOT NULL AFTER alias,
    DROP column certificateSN,
    DROP column certIssuerDN;

ALTER TABLE keyrecoverydata
    ADD column keyData varbinary DEFAULT NULL AFTER markedAsRecoverable,
    DROP column pK,
    MODIFY column certSN varchar(256) DEFAULT '' NOT NULL,
    MODIFY column issuerDN varchar(256) DEFAULT '' NOT NULL,
    DROP column keyPair,
    DROP column PRIMARY KEY,
    ADD PRIMARY KEY (certSN, issuerDN);

#
#  Fieldformats of
#    keyrecoverydata.certSN changed from varchar(250) binary NULL DEFAULT NULL to varchar(250) binary NOT NULL DEFAULT ''.
#    keyrecoverydata.issuerDN changed from varchar(250) binary NULL DEFAULT NULL to varchar(250) binary NOT NULL DEFAULT ''.
#  Possibly data modifications needed!
#

ALTER TABLE logentrydata
    ADD column caId integer NOT NULL DEFAULT '0' AFTER adminData;

ALTER TABLE userdata
    ADD column cAId ineteger DEFAULT '0' NOT NULL AFTER subjectDN,
    ADD column extendedInformationData varbinary DEFAULT NULL AFTER keyStorePassword;



ALTER TABLE accessrulesdata
    ADD rule integer NOT NULL DEFAULT '0' AFTER accessRule,
    ADD isRecursive bit NOT NULL DEFAULT '0' AFTER rule,
    DROP resource,
    MODIFY accessRule varchar(250) NULL DEFAULT NULL,
    MODIFY `AdminGroupData_accessRules` integer NULL DEFAULT NULL;
#
#  Fieldformats of
#    accessrulesdata.accessRule changed from verbinary NULL DEFAULT NULL to varchar(256) NULL DEFAULT NULL.
#    accessrulesdata.AdminGroupData_accessRules changed from varchar(256) NULL DEFAULT NULL to integer NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

ALTER TABLE adminentitydata
    MODIFY matchWith integer NOT NULL DEFAULT '0',
    MODIFY matchType integer NOT NULL DEFAULT '0',
    MODIFY `AdminGroupData_adminEntities` integer NULL DEFAULT NULL;
#
#  Fieldformats of
#    adminentitydata.matchWith changed from integer NULL DEFAULT NULL to integer NOT NULL DEFAULT '0'.
#    adminentitydata.matchType changed from integer NULL DEFAULT NULL to integer NOT NULL DEFAULT '0'.
#    adminentitydata.AdminGroupData_adminEntities changed from varchar(256) NULL DEFAULT NULL to integer NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

ALTER TABLE admingroupdata
    ADD pK integer NOT NULL DEFAULT '0' FIRST,
    ADD cAId integer NOT NULL DEFAULT '0' AFTER adminGroupName,
    MODIFY adminGroupName varchar(256) NULL DEFAULT NULL,
    DROP PRIMARY KEY,
    ADD PRIMARY KEY (pK);
#
#  Fieldformat of
#    admingroupdata.adminGroupName changed from varchar(256) NOT NULL DEFAULT '' to varchar(256) NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

DROP TABLE availableaccessrulesdata;

ALTER TABLE hardtokendata
    ADD significantIssuerDN varchar(256) NULL DEFAULT NULL AFTER tokenType;

ALTER TABLE hardtokenissuerdata
    ADD adminGroupId integer NOT NULL DEFAULT '0' AFTER alias,
    DROP certificateSN,
    DROP certIssuerDN;

ALTER TABLE keyrecoverydata
    ADD keyData varbinary NULL DEFAULT NULL AFTER markedAsRecoverable,
    DROP pK,
    MODIFY certSN varchar(256) NOT NULL DEFAULT '',
    MODIFY issuerDN varchar(256) NOT NULL DEFAULT '',
    DROP keyPair,
    DROP PRIMARY KEY,
    ADD PRIMARY KEY (certSN, issuerDN);

#
#  Fieldformats of
#    keyrecoverydata.certSN changed from varchar(250) binary NULL DEFAULT NULL to varchar(250) binary NOT NULL DEFAULT ''.
#    keyrecoverydata.issuerDN changed from varchar(250) binary NULL DEFAULT NULL to varchar(250) binary NOT NULL DEFAULT ''.
#  Possibly data modifications needed!
#

ALTER TABLE logentrydata
    ADD caId integer NOT NULL DEFAULT '0' AFTER adminData;

ALTER TABLE userdata
    ADD cAId ineteger NOT NULL DEFAULT '0' AFTER subjectDN,
    ADD extendedInformationData varbinary NULL DEFAULT NULL AFTER keyStorePassword;



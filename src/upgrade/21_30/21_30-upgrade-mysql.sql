
ALTER TABLE accessrulesdata
    ADD rule int(11) NOT NULL DEFAULT '0' AFTER accessRule,
    ADD isRecursive tinyint(4) NOT NULL DEFAULT '0' AFTER rule,
    DROP resource,
    MODIFY accessRule varchar(250) binary NULL DEFAULT NULL,
    MODIFY `AdminGroupData_accessRules` int(11) NULL DEFAULT NULL;
#
#  Fieldformats of
#    accessrulesdata.accessRule changed from longblob NULL DEFAULT NULL to varchar(250) binary NULL DEFAULT NULL.
#    accessrulesdata.AdminGroupData_accessRules changed from varchar(250) binary NULL DEFAULT NULL to int(11) NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

ALTER TABLE adminentitydata
    MODIFY matchWith int(11) NOT NULL DEFAULT '0',
    MODIFY matchType int(11) NOT NULL DEFAULT '0',
    MODIFY `AdminGroupData_adminEntities` int(11) NULL DEFAULT NULL;
#
#  Fieldformats of
#    adminentitydata.matchWith changed from int(11) NULL DEFAULT NULL to int(11) NOT NULL DEFAULT '0'.
#    adminentitydata.matchType changed from int(11) NULL DEFAULT NULL to int(11) NOT NULL DEFAULT '0'.
#    adminentitydata.AdminGroupData_adminEntities changed from varchar(250) binary NULL DEFAULT NULL to int(11) NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

ALTER TABLE admingroupdata
    ADD pK int(11) NOT NULL DEFAULT '0' FIRST,
    ADD cAId int(11) NOT NULL DEFAULT '0' AFTER adminGroupName,
    MODIFY adminGroupName varchar(250) binary NULL DEFAULT NULL,
    DROP PRIMARY KEY,
    ADD PRIMARY KEY (pK);
#
#  Fieldformat of
#    admingroupdata.adminGroupName changed from varchar(250) binary NOT NULL DEFAULT '' to varchar(250) binary NULL DEFAULT NULL.
#  Possibly data modifications needed!
#

DROP TABLE availableaccessrulesdata;

ALTER TABLE hardtokendata
    ADD significantIssuerDN varchar(250) binary NULL DEFAULT NULL AFTER tokenType;

ALTER TABLE hardtokenissuerdata
    ADD adminGroupId int(11) NOT NULL DEFAULT '0' AFTER alias,
    DROP certificateSN,
    DROP certIssuerDN;

ALTER TABLE keyrecoverydata
    ADD keyData text NULL DEFAULT NULL AFTER markedAsRecoverable,
    DROP pK,
    MODIFY certSN varchar(250) binary NOT NULL DEFAULT '',
    MODIFY issuerDN varchar(250) binary NOT NULL DEFAULT '',
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
    ADD caId int(11) NOT NULL DEFAULT '0' AFTER adminData;

ALTER TABLE userdata
    ADD cAId int(11) NOT NULL DEFAULT '0' AFTER subjectDN,
    ADD extendedInformationData longblob NULL DEFAULT NULL AFTER keyStorePassword;



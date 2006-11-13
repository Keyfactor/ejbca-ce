MySQL
=====

CREATE TABLE accessrulesdata (
    pK int(11) NOT NULL DEFAULT '0',
    accessRule varchar(250) binary NULL DEFAULT NULL,
    rule int(11) NOT NULL DEFAULT '0',
    isRecursive tinyint(4) NOT NULL DEFAULT '0',
    `AdminGroupData_accessRules` int(11) NULL DEFAULT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE adminentitydata (
    pK int(11) NOT NULL DEFAULT '0',
    matchWith int(11) NOT NULL DEFAULT '0',
    matchType int(11) NOT NULL DEFAULT '0',
    matchValue varchar(250) binary NULL DEFAULT NULL,
    `AdminGroupData_adminEntities` int(11) NULL DEFAULT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE admingroupdata (
    pK int(11) NOT NULL DEFAULT '0',
    adminGroupName varchar(250) binary NULL DEFAULT NULL,
    cAId int(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (pK)
);

CREATE TABLE adminpreferencesdata (
    id varchar(250) binary NOT NULL DEFAULT '',
    data longblob NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE approvaldata (
TODO
);

CREATE TABLE authorizationtreeupdatedata (
    pK int(11) NOT NULL DEFAULT '0',
    authorizationTreeUpdateNumber int(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (pK)
);

CREATE TABLE cadata (
    cAId int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    subjectDN varchar(250) binary NULL DEFAULT NULL,
    status int(11) NOT NULL DEFAULT '0',
    expireTime bigint(20) NOT NULL DEFAULT '0',
    data text NULL DEFAULT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE certificatedata (
    fingerprint varchar(250) binary NOT NULL DEFAULT '',
    issuerDN varchar(250) binary NULL DEFAULT NULL,
    subjectDN varchar(250) binary NULL DEFAULT NULL,
    cAFingerprint varchar(250) binary NULL DEFAULT NULL,
    status int(11) NOT NULL DEFAULT '0',
    type int(11) NOT NULL DEFAULT '0',
    serialNumber varchar(250) binary NULL DEFAULT NULL,
    expireDate bigint(20) NOT NULL DEFAULT '0',
    revocationDate bigint(20) NOT NULL DEFAULT '0',
    revocationReason int(11) NOT NULL DEFAULT '0',
    base64Cert text NULL DEFAULT NULL,
    username varchar(250) binary NULL DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE certificateprofiledata (
    id int(11) NOT NULL DEFAULT '0',
    certificateProfileName varchar(250) binary NULL DEFAULT NULL,
    data longblob NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE certreqhistorydata (
    fingerprint varchar(250) binary NOT NULL DEFAULT '',
    issuerDN varchar(250) binary NULL DEFAULT NULL,
    serialNumber varchar(250) binary NULL DEFAULT NULL,
    `timestamp` bigint(20) NOT NULL DEFAULT '0',
    userDataVO longtext NULL DEFAULT NULL,
    username varchar(250) binary NULL DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE crldata (
    fingerprint varchar(250) binary NOT NULL DEFAULT '',
    cRLNumber int(11) NOT NULL DEFAULT '0',
    issuerDN varchar(250) binary NULL DEFAULT NULL,
    cAFingerprint varchar(250) binary NULL DEFAULT NULL,
    thisUpdate bigint(20) NOT NULL DEFAULT '0',
    nextUpdate bigint(20) NOT NULL DEFAULT '0',
    base64Crl longtext NULL DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE endentityprofiledata (
    id int(11) NOT NULL DEFAULT '0',
    profileName varchar(250) binary NULL DEFAULT NULL,
    data longblob NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE globalconfigurationdata (
    configurationId varchar(250) binary NOT NULL DEFAULT '',
    data longblob NULL DEFAULT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE hardtokencertificatemap (
    certificateFingerprint varchar(250) binary NOT NULL DEFAULT '',
    tokenSN varchar(250) binary NULL DEFAULT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE hardtokendata (
    tokenSN varchar(250) binary NOT NULL DEFAULT '',
    username varchar(250) binary NULL DEFAULT NULL,
    cTime bigint(20) NOT NULL DEFAULT '0',
    mTime bigint(20) NOT NULL DEFAULT '0',
    tokenType int(11) NOT NULL DEFAULT '0',
    significantIssuerDN varchar(250) binary NULL DEFAULT NULL,
    data longblob NULL DEFAULT NULL,
    PRIMARY KEY (tokenSN)
);

CREATE TABLE hardtokenissuerdata (
    id int(11) NOT NULL DEFAULT '0',
    alias varchar(250) binary NULL DEFAULT NULL,
    adminGroupId int(11) NOT NULL DEFAULT '0',
    data longblob NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE hardtokenprofiledata (
    id int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    updateCounter int(11) NOT NULL DEFAULT '0',
    data longtext NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE hardtokenpropertydata (
    id varchar(250) binary NOT NULL DEFAULT '',
    property varchar(250) binary NOT NULL DEFAULT '',
    value varchar(250) binary NULL DEFAULT NULL,
    PRIMARY KEY (id, property)
);

CREATE TABLE keyrecoverydata (
    certSN varchar(250) binary NOT NULL DEFAULT '',
    issuerDN varchar(250) binary NOT NULL DEFAULT '',
    username varchar(250) binary NULL DEFAULT NULL,
    markedAsRecoverable tinyint(4) NOT NULL DEFAULT '0',
    keyData text NULL DEFAULT NULL,
    PRIMARY KEY (certSN, issuerDN)
);

CREATE TABLE logconfigurationdata (
    id int(11) NOT NULL DEFAULT '0',
    logConfiguration longblob NULL DEFAULT NULL,
    logEntryRowNumber int(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (id)
);

CREATE TABLE logentrydata (
    id int(11) NOT NULL DEFAULT '0',
    adminType int(11) NOT NULL DEFAULT '0',
    adminData varchar(250) binary NULL DEFAULT NULL,
    caId int(11) NOT NULL DEFAULT '0',
    module int(11) NOT NULL DEFAULT '0',
    `time` bigint(20) NOT NULL DEFAULT '0',
    username varchar(250) binary NULL DEFAULT NULL,
    certificateSNR varchar(250) binary NULL DEFAULT NULL,
    event int(11) NOT NULL DEFAULT '0',
    comment varchar(250) binary NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE publisherdata (
    id int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    updateCounter int(11) NOT NULL DEFAULT '0',
    data text NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE servicedata (
TODO
);

CREATE TABLE tableprotectdata (
TODO
);

CREATE TABLE servicedata (
TODO
);

CREATE TABLE userdata (
    username varchar(250) binary NOT NULL DEFAULT '',
    subjectDN varchar(250) binary NULL DEFAULT NULL,
    cAId int(11) NOT NULL DEFAULT '0',
    subjectAltName varchar(250) binary NULL DEFAULT NULL,
    subjectEmail varchar(250) binary NULL DEFAULT NULL,
    status int(11) NOT NULL DEFAULT '0',
    type int(11) NOT NULL DEFAULT '0',
    clearPassword varchar(250) binary NULL DEFAULT NULL,
    passwordHash varchar(250) binary NULL DEFAULT NULL,
    timeCreated bigint(20) NOT NULL DEFAULT '0',
    timeModified bigint(20) NOT NULL DEFAULT '0',
    endEntityProfileId int(11) NOT NULL DEFAULT '0',
    certificateProfileId int(11) NOT NULL DEFAULT '0',
    tokenType int(11) NOT NULL DEFAULT '0',
    hardTokenIssuerId int(11) NOT NULL DEFAULT '0',
    extendedInformationData longtext NULL DEFAULT NULL,
    keyStorePassword varchar(250) binary NULL DEFAULT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE userdatasourcedata (
TODO
);

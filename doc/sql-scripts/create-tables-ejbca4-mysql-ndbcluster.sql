-- This script assumes that the tablespace 'ejbca_ts' exists.

CREATE TABLE AccessRulesData (
    pK int(11) NOT NULL DEFAULT '0',
    accessRule varchar(250) binary NULL DEFAULT NULL,
    rule int(11) NOT NULL DEFAULT '0',
    isRecursive tinyint(4) NOT NULL DEFAULT '0',
    `AdminGroupData_accessRules` int(11) NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (pK)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE AdminEntityData (
    pK int(11) NOT NULL DEFAULT '0',
    matchWith int(11) NOT NULL DEFAULT '0',
    matchType int(11) NOT NULL DEFAULT '0',
    matchValue varchar(250) binary NULL DEFAULT NULL,
    `AdminGroupData_adminEntities` int(11) NULL DEFAULT NULL,
    cAId int(11) NOT NULL DEFAULT '0',
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (pK)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE AdminGroupData (
    pK int(11) NOT NULL DEFAULT '0',
    adminGroupName varchar(250) binary NULL DEFAULT NULL,
    cAId int(11) NOT NULL DEFAULT '0',
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (pK)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE AdminPreferencesData (
    id varchar(250) binary NOT NULL DEFAULT '',
    data longblob NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE ApprovalData (
    id int(11) NOT NULL DEFAULT '0',
    approvalid int(11) NOT NULL DEFAULT '0',
    approvaltype int(11) NOT NULL DEFAULT '0',
    endentityprofileid int(11) NOT NULL DEFAULT '0',
    caid int(11) NOT NULL DEFAULT '0',
    reqadmincertissuerdn varchar(250) binary NULL DEFAULT NULL,
    reqadmincertsn varchar(250) binary NULL DEFAULT NULL,
    status int(11) NOT NULL DEFAULT '0',
    approvaldata longtext NULL DEFAULT NULL,
    requestdata longtext NULL DEFAULT NULL,    
    requestdate bigint(20) NOT NULL DEFAULT '0',
    expiredate bigint(20) NOT NULL DEFAULT '0',    
    remainingapprovals int(11) NOT NULL DEFAULT '0',
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE AuthorizationTreeUpdateData (
    pK int(11) NOT NULL DEFAULT '0',
    authorizationTreeUpdateNumber int(11) NOT NULL DEFAULT '0',
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (pK)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE CAData (
    cAId int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    subjectDN varchar(250) binary NULL DEFAULT NULL,
    status int(11) NOT NULL DEFAULT '0',
    expireTime bigint(20) NOT NULL DEFAULT '0',
    updateTime bigint(20) NOT NULL DEFAULT '0',
    data longtext NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (cAId)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE CRLData (
    fingerprint varchar(250) binary NOT NULL DEFAULT '',
    cRLNumber int(11) NOT NULL DEFAULT '0',
    issuerDN varchar(250) binary NULL DEFAULT NULL,
    cAFingerprint varchar(250) binary NULL DEFAULT NULL,
    thisUpdate bigint(20) NOT NULL DEFAULT '0',
    nextUpdate bigint(20) NOT NULL DEFAULT '0',
    deltaCRLIndicator int(11) NOT NULL DEFAULT '-1',
    base64Crl longtext NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (fingerprint)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE CertReqHistoryData (
    fingerprint varchar(250) binary NOT NULL DEFAULT '',
    issuerDN varchar(250) binary NULL DEFAULT NULL,
    serialNumber varchar(250) binary NULL DEFAULT NULL,
    `timestamp` bigint(20) NOT NULL DEFAULT '0',
    userDataVO longtext NULL DEFAULT NULL,
    username varchar(250) binary NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (fingerprint)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE CertificateData (
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
    base64Cert longtext NULL DEFAULT NULL,
    username varchar(250) binary NULL DEFAULT NULL,
    tag varchar(250) binary NULL DEFAULT NULL,
    certificateProfileId int(11) NULL DEFAULT '0',
    updateTime bigint(20) NOT NULL DEFAULT '0',
    subjectKeyId varchar(250) binary NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (fingerprint)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE CertificateProfileData (
    id int(11) NOT NULL DEFAULT '0',
    certificateProfileName varchar(250) binary NULL DEFAULT NULL,
    data longblob NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE EndEntityProfileData (
    id int(11) NOT NULL DEFAULT '0',
    profileName varchar(250) binary NULL DEFAULT NULL,
    data longblob NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE GlobalConfigurationData (
    configurationId varchar(250) binary NOT NULL DEFAULT '',
    data longblob NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (configurationId)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint varchar(250) binary NOT NULL DEFAULT '',
    tokenSN varchar(250) binary NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (certificateFingerprint)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE HardTokenData (
    tokenSN varchar(250) binary NOT NULL DEFAULT '',
    username varchar(250) binary NULL DEFAULT NULL,
    cTime bigint(20) NOT NULL DEFAULT '0',
    mTime bigint(20) NOT NULL DEFAULT '0',
    tokenType int(11) NOT NULL DEFAULT '0',
    significantIssuerDN varchar(250) binary NULL DEFAULT NULL,
    data longblob NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (tokenSN)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE HardTokenIssuerData (
    id int(11) NOT NULL DEFAULT '0',
    alias varchar(250) binary NULL DEFAULT NULL,
    adminGroupId int(11) NOT NULL DEFAULT '0',
    data longblob NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE HardTokenProfileData (
    id int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    updateCounter int(11) NOT NULL DEFAULT '0',
    data longtext NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE HardTokenPropertyData (
    id varchar(80) binary NOT NULL DEFAULT '',
    property varchar(250) binary NOT NULL DEFAULT '',
    value varchar(250) binary NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id, property)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE KeyRecoveryData (
    certSN varchar(250) binary NOT NULL DEFAULT '',
    issuerDN varchar(250) binary NOT NULL DEFAULT '',
    username varchar(250) binary NULL DEFAULT NULL,
    markedAsRecoverable tinyint(4) NOT NULL DEFAULT '0',
    keyData longtext NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (certSN, issuerDN)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE LogConfigurationData (
    id int(11) NOT NULL DEFAULT '0',
    logConfiguration longblob NULL DEFAULT NULL,
    logEntryRowNumber int(11) NOT NULL DEFAULT '0',
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE LogEntryData (
    id int(11) NOT NULL DEFAULT '0',
    adminType int(11) NOT NULL DEFAULT '0',
    adminData varchar(250) binary NULL DEFAULT NULL,
    caId int(11) NOT NULL DEFAULT '0',
    module int(11) NOT NULL DEFAULT '0',
    `time` bigint(20) NOT NULL DEFAULT '0',
    username varchar(250) binary NULL DEFAULT NULL,
    certificateSNR varchar(250) binary NULL DEFAULT NULL,
    event int(11) NOT NULL DEFAULT '0',
    logComment varchar(250) binary NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE PublisherData (
    id int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    updateCounter int(11) NOT NULL DEFAULT '0',
    data longtext NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE PublisherQueueData (
    pk varchar(250) binary NOT NULL DEFAULT '',
    timeCreated bigint(20) NOT NULL DEFAULT '0',
    lastUpdate bigint(20) NOT NULL DEFAULT '0',
    publishStatus int(11) NOT NULL DEFAULT '0',
    tryCounter int(11) NOT NULL DEFAULT '0',
    publishType int(11) NOT NULL DEFAULT '0',
    fingerprint varchar(250) binary NULL DEFAULT NULL,
    publisherId int(11) NOT NULL DEFAULT '0',
    volatileData longtext NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (pk)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE ServiceData (
    id int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    data longtext NULL DEFAULT NULL,
    nextRunTimeStamp bigint(20) NOT NULL DEFAULT '0',
    runTimeStamp bigint(20) NOT NULL DEFAULT '0',    
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE UserData (
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
    cardnumber varchar(19) binary NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (username)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

CREATE TABLE UserDataSourceData (
    id int(11) NOT NULL DEFAULT '0',
    name varchar(250) binary NULL DEFAULT NULL,
    updateCounter int(11) NOT NULL DEFAULT '0',
    data longtext NULL DEFAULT NULL,
    rowVersion int(11) DEFAULT 0,
    rowProtection longtext DEFAULT NULL,
    PRIMARY KEY (id)
) TABLESPACE ejbca_ts STORAGE DISK ENGINE=NDB;

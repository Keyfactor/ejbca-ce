CREATE TABLE AccessRulesData (
    primKey int NOT NULL DEFAULT '0',
    accessRule varchar(250) NULL DEFAULT NULL,
    rule9 int NOT NULL DEFAULT '0',
    isRecursive tinyint NOT NULL DEFAULT '0',
    AdminGroupData_primKey int NULL DEFAULT NULL,
    PRIMARY KEY (primKey)
);

CREATE TABLE AdminEntityData (
    primKey int NOT NULL DEFAULT '0',
    matchWith int NOT NULL DEFAULT '0',
    matchType int NOT NULL DEFAULT '0',
    matchValue varchar(250) NULL DEFAULT NULL,
    AdminGroupData_primKey96 int NULL DEFAULT NULL,
    cAId int NOT NULL DEFAULT '0',
    PRIMARY KEY (primKey)
);

CREATE TABLE AdminGroupData (
    primKey int NOT NULL DEFAULT '0',
    adminGroupName varchar(250) NULL DEFAULT NULL,
    cAId int NOT NULL DEFAULT '0',
    PRIMARY KEY (primKey)
);

CREATE TABLE AdminPreferencesData (
    id varchar(250) NOT NULL DEFAULT '',
    data image NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ApprovalData (
    id int NOT NULL DEFAULT '0',
    approvalid int NOT NULL DEFAULT '0',
    approvaltype int NOT NULL DEFAULT '0',
    endentityprofileid int NOT NULL DEFAULT '0',
    caid int NOT NULL DEFAULT '0',
    reqadmincertissuerdn varchar(250) NULL DEFAULT NULL,
    reqadmincertsn varchar(250) NULL DEFAULT NULL,
    status int NOT NULL DEFAULT '0',
    approvaldata text NULL DEFAULT NULL,
    requestdata text NULL DEFAULT NULL,    
    requestdate bigint NOT NULL DEFAULT '0',
    expiredate bigint NOT NULL DEFAULT '0',    
    remainingapprovals int NOT NULL DEFAULT '0',
    PRIMARY KEY (id)
);

CREATE TABLE AuthorizationTreeUpdateData (
    primKey int NOT NULL DEFAULT '0',
    authorizationTreeUpdateNumber int NOT NULL DEFAULT '0',
    PRIMARY KEY (primKey)
);

CREATE TABLE CAData (
    cAId int NOT NULL DEFAULT '0',
    name varchar(250) NULL DEFAULT NULL,
    subjectDN varchar(250) NULL DEFAULT NULL,
    status int NOT NULL DEFAULT '0',
    expireTime bigint NOT NULL DEFAULT '0',
    updateTime bigint NOT NULL DEFAULT '0',
    data text NULL DEFAULT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint varchar(250) NOT NULL DEFAULT '',
    cRLNumber int NOT NULL DEFAULT '0',
    issuerDN varchar(250) NULL DEFAULT NULL,
    cAFingerprint varchar(250) NULL DEFAULT NULL,
    thisUpdate bigint NOT NULL DEFAULT '0',
    nextUpdate bigint NOT NULL DEFAULT '0',
    deltaCRLIndicator int NOT NULL DEFAULT '-1',
    base64Crl text NULL DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint varchar(250) NOT NULL DEFAULT '',
    issuerDN varchar(250) NULL DEFAULT NULL,
    serialNumber varchar(250) NULL DEFAULT NULL,
    timestamp9 bigint NOT NULL DEFAULT '0',
    userDataVO text NULL DEFAULT NULL,
    username varchar(250) NULL DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateData (
    fingerprint varchar(250) NOT NULL DEFAULT '',
    issuerDN varchar(250) NULL DEFAULT NULL,
    subjectDN varchar(250) NULL DEFAULT NULL,
    cAFingerprint varchar(250) NULL DEFAULT NULL,
    status int NOT NULL DEFAULT '0',
    type int NOT NULL DEFAULT '0',
    serialNumber varchar(250) NULL DEFAULT NULL,
    expireDate bigint NOT NULL DEFAULT '0',
    revocationDate bigint NOT NULL DEFAULT '0',
    revocationReason int NOT NULL DEFAULT '0',
    base64Cert text NULL DEFAULT NULL,
    username varchar(250) NULL DEFAULT NULL,
    tag varchar(250) NULL DEFAULT NULL,
    certificateProfileId int NULL DEFAULT '0',
    updateTime bigint NOT NULL DEFAULT '0',
    subjectKeyId varchar(250) NULL DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateProfileData (
    id int NOT NULL DEFAULT '0',
    certificateProfileName varchar(250) NULL DEFAULT NULL,
    data image NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id int NOT NULL DEFAULT '0',
    profileName varchar(250) NULL DEFAULT NULL,
    data image NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId varchar(250) NOT NULL DEFAULT '',
    data image NULL DEFAULT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint varchar(250) NOT NULL DEFAULT '',
    tokenSN varchar(250) NULL DEFAULT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN varchar(250) NOT NULL DEFAULT '',
    username varchar(250) NULL DEFAULT NULL,
    cTime bigint NOT NULL DEFAULT '0',
    mTime bigint NOT NULL DEFAULT '0',
    tokenType int NOT NULL DEFAULT '0',
    significantIssuerDN varchar(250) NULL DEFAULT NULL,
    data image NULL DEFAULT NULL,
    PRIMARY KEY (tokenSN)
);

CREATE TABLE HardTokenIssuerData (
    id int NOT NULL DEFAULT '0',
    alias varchar(250) NULL DEFAULT NULL,
    adminGroupId int NOT NULL DEFAULT '0',
    data image NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id int NOT NULL DEFAULT '0',
    name varchar(250) NULL DEFAULT NULL,
    updateCounter int NOT NULL DEFAULT '0',
    data text NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id varchar(250) NOT NULL DEFAULT '',
    property varchar(250) NOT NULL DEFAULT '',
    value varchar(250) NULL DEFAULT NULL,
    PRIMARY KEY (id, property)
);

CREATE TABLE KeyRecoveryData (
    certSN varchar(250) NOT NULL DEFAULT '',
    issuerDN varchar(250) NOT NULL DEFAULT '',
    username varchar(250) NULL DEFAULT NULL,
    markedAsRecoverable tinyint NOT NULL DEFAULT '0',
    keyData text NULL DEFAULT NULL,
    PRIMARY KEY (certSN, issuerDN)
);

CREATE TABLE LogConfigurationData (
    id int NOT NULL DEFAULT '0',
    logConfiguration image NULL DEFAULT NULL,
    logEntryRowNumber int NOT NULL DEFAULT '0',
    PRIMARY KEY (id)
);

CREATE TABLE LogEntryData (
    id int NOT NULL DEFAULT '0',
    adminType int NOT NULL DEFAULT '0',
    adminData varchar(250) NULL DEFAULT NULL,
    caId int NOT NULL DEFAULT '0',
    module9 int NOT NULL DEFAULT '0',
    time9 bigint NOT NULL DEFAULT '0',
    username varchar(250) NULL DEFAULT NULL,
    certificateSNR varchar(250) NULL DEFAULT NULL,
    event int NOT NULL DEFAULT '0',
    logComment varchar(250) NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ProtectedLogData (
	pk varchar(250) NOT NULL DEFAULT '',
	adminType int NOT NULL DEFAULT '0',
	adminData varchar(250) NULL DEFAULT NULL,
    caId int NOT NULL DEFAULT '0',
    module int NOT NULL DEFAULT '0',
    eventTime bigint NOT NULL DEFAULT '0',
    username varchar(250) NULL DEFAULT NULL,
    certificateSerialNumber varchar(250) NULL DEFAULT NULL,
    certificateIssuerDN varchar(250) NULL DEFAULT NULL,
    eventId int NOT NULL DEFAULT '0',
    eventComment text NULL DEFAULT NULL,
    nodeGUID int NOT NULL DEFAULT '0',
    counter bigint NOT NULL DEFAULT '0',
    nodeIP varchar(250) NULL DEFAULT NULL,
    b64LinkedInEventIdentifiers text NULL DEFAULT NULL,
    b64LinkedInEventsHash varchar(250) NULL DEFAULT NULL,
    currentHashAlgorithm varchar(250) NULL DEFAULT NULL,
    protectionKeyIdentifier int NOT NULL DEFAULT '0',
    protectionKeyAlgorithm varchar(250) NULL DEFAULT NULL,
    b64Protection text NULL DEFAULT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE ProtectedLogExportData (
	pk varchar(250) NOT NULL DEFAULT '',
    timeOfExport bigint NOT NULL DEFAULT '0',
    exportEndTime bigint NOT NULL DEFAULT '0',
    exportStartTime bigint NOT NULL DEFAULT '0',
    b64LogDataHash varchar(250) NULL DEFAULT NULL,
    b64PreviosExportHash varchar(250) NULL DEFAULT NULL,
    currentHashAlgorithm varchar(250) NULL DEFAULT NULL,
    b64SignatureCertificate text NULL DEFAULT NULL,
    deleted tinyint NOT NULL DEFAULT '0',
    b64Signature text NULL DEFAULT NULL,
	PRIMARY KEY (pk)
);

CREATE TABLE ProtectedLogTokenData (
	pk varchar(250) NOT NULL DEFAULT '',
    tokenIdentifier int NOT NULL DEFAULT '0',
    tokenType int NOT NULL DEFAULT '0',
    b64TokenCertificate text NULL DEFAULT NULL,
    tokenReference text NULL DEFAULT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE PublisherData (
    id int NOT NULL DEFAULT '0',
    name varchar(250) NULL DEFAULT NULL,
    updateCounter int NOT NULL DEFAULT '0',
    data text NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherQueueData (
    pk varchar(250) NOT NULL DEFAULT '',
    timeCreated bigint NOT NULL DEFAULT '0',
    lastUpdate bigint NOT NULL DEFAULT '0',
    publishStatus int NOT NULL DEFAULT '0',
    tryCounter int NOT NULL DEFAULT '0',
    publishType int NOT NULL DEFAULT '0',
    fingerprint varchar(250) NULL DEFAULT NULL,
    publisherId int NOT NULL DEFAULT '0',
    volatileData text NULL DEFAULT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE ServiceData (
    id int NOT NULL DEFAULT '0',
    name varchar(250) NULL DEFAULT NULL,
    data text NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE TableProtectData (
    id varchar(250) NOT NULL DEFAULT '',
    version int NOT NULL DEFAULT '0',
    hashVersion int NOT NULL DEFAULT '0',
    protectionAlg varchar(250) NULL DEFAULT NULL,
    hash varchar(250) NULL DEFAULT NULL,
    signature varchar(250) NULL DEFAULT NULL,
    time bigint NOT NULL DEFAULT '0',
    dbKey varchar(250) NULL DEFAULT NULL,
    dbType varchar(250) NULL DEFAULT NULL,
    keyType varchar(250) NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE UserData (
    username varchar(250) NOT NULL DEFAULT '',
    subjectDN varchar(250) NULL DEFAULT NULL,
    cAId int NOT NULL DEFAULT '0',
    subjectAltName varchar(250) NULL DEFAULT NULL,
    subjectEmail varchar(250) NULL DEFAULT NULL,
    status int NOT NULL DEFAULT '0',
    type int NOT NULL DEFAULT '0',
    clearPassword varchar(250) NULL DEFAULT NULL,
    passwordHash varchar(250) NULL DEFAULT NULL,
    timeCreated bigint NOT NULL DEFAULT '0',
    timeModified bigint NOT NULL DEFAULT '0',
    endEntityProfileId int NOT NULL DEFAULT '0',
    certificateProfileId int NOT NULL DEFAULT '0',
    tokenType int NOT NULL DEFAULT '0',
    hardTokenIssuerId int NOT NULL DEFAULT '0',
    extendedInformationData text NULL DEFAULT NULL,
    keyStorePassword varchar(250) NULL DEFAULT NULL,
    cardnumber varchar(19) NULL DEFAULT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id int NOT NULL DEFAULT '0',
    name varchar(250) NULL DEFAULT NULL,
    updateCounter int NOT NULL DEFAULT '0',
    data text NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

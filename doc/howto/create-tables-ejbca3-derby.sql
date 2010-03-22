--
-- These definitions should work for EJBCA 3.10.x, Derby 10.1 or 10.2.
--

DROP TABLE AccessRulesData;
CREATE TABLE AccessRulesData (
    pK integer NOT NULL,
    accessRule varchar(256),
    rule integer NOT NULL,
    isRecursive smallint NOT NULL,
    AdminGroupData_accessRules integer DEFAULT NULL,
    PRIMARY KEY (pK)
);

DROP TABLE AdminEntityData;
CREATE TABLE AdminEntityData (
    pK integer NOT NULL,
    matchWith integer NOT NULL,
    matchType integer NOT NULL,
    matchValue varchar(256),
    AdminGroupData_adminEntities integer DEFAULT NULL,
    cAId integer NOT NULL,
    PRIMARY KEY (pK)
);

DROP TABLE AdminGroupData;
CREATE TABLE AdminGroupData (
    pK integer NOT NULL,
    adminGroupName varchar(256),
    cAId integer NOT NULL,
    PRIMARY KEY (pK)
);

DROP TABLE AdminPreferencesData;
CREATE TABLE AdminPreferencesData (
    id varchar(256) NOT NULL DEFAULT '',
    data blob,
    PRIMARY KEY (id)
);

DROP TABLE ApprovalData;
CREATE TABLE ApprovalData (
    id integer NOT NULL,
    approvalid integer NOT NULL,
    approvaltype integer NOT NULL,
    endentityprofileid integer NOT NULL,
    caid integer NOT NULL,
    reqadmincertissuerdn varchar(256),
    reqadmincertsn varchar(256),
    status integer NOT NULL,
    approvaldata clob,
    requestdata clob,    
    requestdate bigint NOT NULL,
    expiredate bigint NOT NULL,    
    remainingapprovals integer NOT NULL,
    PRIMARY KEY (id)
);

DROP TABLE AuthorizationTreeUpdateData;
CREATE TABLE AuthorizationTreeUpdateData (
    pK integer NOT NULL,
    authorizationTreeUpdateNumber integer NOT NULL,
    PRIMARY KEY (pK)
);

DROP TABLE CAData;
CREATE TABLE CAData (
    cAId integer NOT NULL,
    name varchar(256),
    subjectDN varchar(256),
    status integer NOT NULL,
    expireTime bigint NOT NULL,
    updateTime bigint NOT NULL,
    data clob,
    PRIMARY KEY (cAId)
);

DROP TABLE CRLData;
CREATE TABLE CRLData (
    fingerprint varchar(256)NOT NULL,
    cRLNumber integer NOT NULL,
    issuerDN varchar(256),
    cAFingerprint varchar(256),
    thisUpdate bigint NOT NULL,
    nextUpdate bigint NOT NULL,
    deltaCRLIndicator integer NOT NULL,
    base64Crl clob,
    PRIMARY KEY (fingerprint)
);

DROP TABLE CertReqHistoryData;
CREATE TABLE CertReqHistoryData (
    fingerprint varchar(256)NOT NULL,
    issuerDN varchar(256),
    serialNumber varchar(256),
    timestamp bigint NOT NULL,
    userDataVO clob,
    username varchar(256),
    PRIMARY KEY (fingerprint)
);

DROP TABLE CertificateData;
CREATE TABLE CertificateData (
    fingerprint varchar(256)NOT NULL,
    issuerDN varchar(256),
    subjectDN varchar(256),
    cAFingerprint varchar(256),
    status integer NOT NULL,
    type integer NOT NULL,
    serialNumber varchar(256),
    expireDate bigint NOT NULL,
    revocationDate bigint NOT NULL,
    revocationReason integer NOT NULL,
    base64Cert long varchar,
    username varchar(256),
    tag varchar(256),
    certificateProfileId integer,
    updateTime bigint NOT NULL,
    subjectKeyId varchar(256),
    PRIMARY KEY (fingerprint)
);

DROP TABLE CertificateProfileData;
CREATE TABLE CertificateProfileData (
    id integer NOT NULL,
    certificateProfileName varchar(256),
    data blob,
    PRIMARY KEY (id)
);

DROP TABLE EndEntityProfileData;
CREATE TABLE EndEntityProfileData (
    id integer NOT NULL,
    profileName varchar(256),
    data blob,
    PRIMARY KEY (id)
);

DROP TABLE GlobalConfigurationData;
CREATE TABLE GlobalConfigurationData (
    configurationId varchar(256) NOT NULL,
    data blob,
    PRIMARY KEY (configurationId)
);

DROP TABLE HardTokenCertificateMap;
CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint varchar(256) NOT NULL,
    tokenSN varchar(256),
    PRIMARY KEY (certificateFingerprint)
);

DROP TABLE HardTokenData;
CREATE TABLE HardTokenData (
    tokenSN varchar(256) NOT NULL,
    username varchar(256),
    cTime bigint NOT NULL,
    mTime bigint NOT NULL,
    tokenType integer NOT NULL,
    significantIssuerDN varchar(256),
    data blob,
    PRIMARY KEY (tokenSN)
);

DROP TABLE HardTokenIssuerData;
CREATE TABLE HardTokenIssuerData (
    id integer NOT NULL,
    alias varchar(256),
    adminGroupId integer NOT NULL,
    data blob,
    PRIMARY KEY (id)
);

DROP TABLE HardTokenProfileData;
CREATE TABLE HardTokenProfileData (
    id integer NOT NULL,
    name varchar(256),
    updateCounter integer NOT NULL,
    data clob,
    PRIMARY KEY (id)
);

DROP TABLE HardTokenPropertyData;
CREATE TABLE HardTokenPropertyData (
    id varchar(256) NOT NULL,
    property varchar(256) NOT NULL,
    value varchar(256),
    PRIMARY KEY (id, property)
);

DROP TABLE KeyRecoveryData;
CREATE TABLE KeyRecoveryData (
    certSN varchar(256) NOT NULL,
    issuerDN varchar(256) NOT NULL,
    username varchar(256),
    markedAsRecoverable smallint NOT NULL,
    keyData long varchar,
    PRIMARY KEY (certSN, issuerDN)
);

DROP TABLE LogConfigurationData;
CREATE TABLE LogConfigurationData (
    id integer NOT NULL,
    logConfiguration blob,
    logEntryRowNumber integer NOT NULL,
    PRIMARY KEY (id)
);

DROP TABLE LogEntryData;
CREATE TABLE LogEntryData (
    id integer NOT NULL,
    adminType integer NOT NULL,
    adminData varchar(256),
    caId integer NOT NULL,
    module integer NOT NULL,
    time bigint NOT NULL,
    username varchar(256),
    certificateSNR varchar(256),
    event integer NOT NULL,
    logComment varchar(256),
    PRIMARY KEY (id)
);

DROP TABLE ProtectedLogData;
CREATE TABLE ProtectedLogData (
	pk varchar(256) NOT NULL,
	adminType integer NOT NULL,
	adminData varchar(256),
    caId integer NOT NULL,
    module integer NOT NULL,
    eventTime bigint NOT NULL,
    username varchar(256),
    certificateSerialNumber varchar(256),
    certificateIssuerDN varchar(256),
    eventId integer NOT NULL,
    eventComment VARCHAR(32672),
    nodeGUID integer NOT NULL,
    counter bigint NOT NULL,
    nodeIP varchar(256),
    b64LinkedInEventIdentifiers long varchar,
    b64LinkedInEventsHash varchar(256),
    currentHashAlgorithm varchar(256),
    protectionKeyIdentifier integer NOT NULL,
    protectionKeyAlgorithm varchar(256),
    b64Protection long varchar,
    PRIMARY KEY (pk)
);

DROP TABLE ProtectedLogExportData;
CREATE TABLE ProtectedLogExportData (
	pk varchar(256) NOT NULL,
    timeOfExport bigint NOT NULL,
    exportEndTime bigint NOT NULL,
    exportStartTime bigint NOT NULL,
    b64LogDataHash varchar(256),
    b64PreviosExportHash varchar(256),
    currentHashAlgorithm varchar(256),
    b64SignatureCertificate long varchar,
    deleted integer NOT NULL DEFAULT 0,
    b64Signature long varchar,
	PRIMARY KEY (pk)
);

DROP TABLE ProtectedLogTokenData;
CREATE TABLE ProtectedLogTokenData (
	pk varchar(256) NOT NULL,
    tokenIdentifier integer NOT NULL,
    tokenType integer NOT NULL,
    b64TokenCertificate long varchar,
    tokenReference VARCHAR(32672),
    PRIMARY KEY (pk)
);

DROP TABLE PublisherData;
CREATE TABLE PublisherData (
    id integer NOT NULL,
    name varchar(256),
    updateCounter integer NOT NULL,
    data long varchar,
    PRIMARY KEY (id)
);

DROP TABLE PublisherQueueData;
CREATE TABLE PublisherQueueData (
    pk varchar(250) NOT NULL,
    timeCreated bigint NOT NULL,
    lastUpdate bigint NOT NULL,
    publishStatus integer NOT NULL,
    tryCounter integer NOT NULL,
    publishType integer NOT NULL,
    fingerprint varchar(256),
    publisherId integer NOT NULL,
    volatileData long varchar,
    PRIMARY KEY (pk)
);

DROP TABLE ServiceData;
CREATE TABLE ServiceData (
    id integer NOT NULL,
    name varchar(256),
    data long varchar,
    PRIMARY KEY (id)
);

DROP TABLE TableProtectData;
CREATE TABLE TableProtectData (
    id varchar(256) NOT NULL,
    version integer NOT NULL,
    hashVersion integer NOT NULL,
    protectionAlg varchar(256),
    hash varchar(256),
    signature varchar(256),
    time bigint NOT NULL,
    dbKey varchar(256),
    dbType varchar(256),
    keyType varchar(256),
    PRIMARY KEY (id)
);

DROP TABLE UserData;
CREATE TABLE UserData (
    username varchar(256) NOT NULL,
    subjectDN varchar(256),
    cAId integer NOT NULL,
    subjectAltName varchar(256),
    subjectEmail varchar(256),
    status integer NOT NULL,
    type integer NOT NULL,
    clearPassword varchar(256),
    passwordHash varchar(256),
    timeCreated bigint NOT NULL,
    timeModified bigint NOT NULL,
    endEntityProfileId integer NOT NULL,
    certificateProfileId integer NOT NULL,
    tokenType integer NOT NULL,
    hardTokenIssuerId integer NOT NULL,
    extendedInformationData clob,
    keyStorePassword varchar(256),
    cardnumber varchar(19),
    PRIMARY KEY (username)
);

DROP TABLE UserDataSourceData;
CREATE TABLE UserDataSourceData (
    id integer NOT NULL,
    name varchar(256),
    updateCounter integer NOT NULL,
    data long varchar,
    PRIMARY KEY (id)
);

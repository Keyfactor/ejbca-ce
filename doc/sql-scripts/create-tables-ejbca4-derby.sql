CREATE TABLE AccessRulesData (
    pK integer NOT NULL,
    accessRule varchar(256),
    rule integer NOT NULL,
    isRecursive smallint NOT NULL,
    AdminGroupData_accessRules integer DEFAULT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminEntityData (
    pK integer NOT NULL,
    matchWith integer NOT NULL,
    matchType integer NOT NULL,
    matchValue varchar(256),
    AdminGroupData_adminEntities integer DEFAULT NULL,
    cAId integer NOT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK integer NOT NULL,
    adminGroupName varchar(256),
    cAId integer NOT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminPreferencesData (
    id varchar(256) NOT NULL DEFAULT '',
    data blob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

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
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE AuthorizationTreeUpdateData (
    pK integer NOT NULL,
    authorizationTreeUpdateNumber integer NOT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE CAData (
    cAId integer NOT NULL,
    name varchar(256),
    subjectDN varchar(256),
    status integer NOT NULL,
    expireTime bigint NOT NULL,
    updateTime bigint NOT NULL,
    data clob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint varchar(256)NOT NULL,
    cRLNumber integer NOT NULL,
    issuerDN varchar(256),
    cAFingerprint varchar(256),
    thisUpdate bigint NOT NULL,
    nextUpdate bigint NOT NULL,
    deltaCRLIndicator integer NOT NULL,
    base64Crl clob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint varchar(256)NOT NULL,
    issuerDN varchar(256),
    serialNumber varchar(256),
    timestamp bigint NOT NULL,
    userDataVO clob,
    username varchar(256),
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

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
    base64Cert clob DEFAULT NULL,
    username varchar(256),
    tag varchar(256),
    certificateProfileId integer,
    updateTime bigint NOT NULL,
    subjectKeyId varchar(256),
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateProfileData (
    id integer NOT NULL,
    certificateProfileName varchar(256),
    data blob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id integer NOT NULL,
    profileName varchar(256),
    data blob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId varchar(256) NOT NULL,
    data blob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint varchar(256) NOT NULL,
    tokenSN varchar(256),
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN varchar(256) NOT NULL,
    username varchar(256),
    cTime bigint NOT NULL,
    mTime bigint NOT NULL,
    tokenType integer NOT NULL,
    significantIssuerDN varchar(256),
    data blob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (tokenSN)
);

CREATE TABLE HardTokenIssuerData (
    id integer NOT NULL,
    alias varchar(256),
    adminGroupId integer NOT NULL,
    data blob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id integer NOT NULL,
    name varchar(256),
    updateCounter integer NOT NULL,
    data clob,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id varchar(256) NOT NULL,
    property varchar(256) NOT NULL,
    value varchar(256),
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id, property)
);

CREATE TABLE KeyRecoveryData (
    certSN varchar(256) NOT NULL,
    issuerDN varchar(256) NOT NULL,
    username varchar(256),
    markedAsRecoverable smallint NOT NULL,
    keyData clob DEFAULT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (certSN, issuerDN)
);

CREATE TABLE LogConfigurationData (
    id integer NOT NULL,
    logConfiguration blob,
    logEntryRowNumber integer NOT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

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
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherData (
    id integer NOT NULL,
    name varchar(256),
    updateCounter integer NOT NULL,
    data clob DEFAULT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherQueueData (
    pk varchar(250) NOT NULL,
    timeCreated bigint NOT NULL,
    lastUpdate bigint NOT NULL,
    publishStatus integer NOT NULL,
    tryCounter integer NOT NULL,
    publishType integer NOT NULL,
    fingerprint varchar(256),
    publisherId integer NOT NULL,
    volatileData clob DEFAULT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE ServiceData (
    id integer NOT NULL,
    name varchar(256),
    data clob DEFAULT NULL,
    nextRunTimeStamp BIGINT NOT NULL WITH DEFAULT 0,
    runTimeStamp BIGINT NOT NULL WITH DEFAULT 0,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (id)
);

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
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    rowProtection CLOB(10 K) DEFAULT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id integer NOT NULL,
    name varchar(256),
    updateCounter integer NOT NULL,
    data clob DEFAULT NULL,
    rowVersion INTEGER NOT NULL WITH DEFAULT 0,
    PRIMARY KEY (id)
);

CREATE TABLE AccessRulesData (
    pK INTEGER NOT NULL,
    accessRule VARCHAR(255,0) NOT NULL,
    isRecursive BOOLEAN NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    rule INTEGER NOT NULL,
    AdminGroupData_accessRules INTEGER,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminEntityData (
    pK INTEGER NOT NULL,
    cAId INTEGER NOT NULL,
    matchType INTEGER NOT NULL,
    matchValue VARCHAR(255,0),
    matchWith INTEGER NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    tokenType VARCHAR(255,0),
    AdminGroupData_adminEntities INTEGER,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK INTEGER NOT NULL,
    adminGroupName VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminPreferencesData (
    id VARCHAR(255,0) NOT NULL,
    data BLOB NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ApprovalData (
    id INTEGER NOT NULL,
    approvalData TEXT NOT NULL,
    approvalId INTEGER NOT NULL,
    approvalType INTEGER NOT NULL,
    cAId INTEGER NOT NULL,
    approvalProfileId INTEGER,
    endEntityProfileId INTEGER NOT NULL,
    expireDate DECIMAL(18,0) NOT NULL,
    remainingApprovals INTEGER NOT NULL,
    reqAdminCertIssuerDn VARCHAR(255,0),
    reqAdminCertSn VARCHAR(255,0),
    requestData TEXT NOT NULL,
    requestDate DECIMAL(18,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    status INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE AuditRecordData (
    pk VARCHAR(255,0) NOT NULL,
    additionalDetails TEXT,
    authToken VARCHAR(255,0) NOT NULL,
    customId VARCHAR(255,0),
    eventStatus VARCHAR(255,0) NOT NULL,
    eventType VARCHAR(255,0) NOT NULL,
    module VARCHAR(255,0) NOT NULL,
    nodeId VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    searchDetail1 VARCHAR(255,0),
    searchDetail2 VARCHAR(255,0),
    sequenceNumber DECIMAL(18,0) NOT NULL,
    service VARCHAR(255,0) NOT NULL,
    timeStamp DECIMAL(18,0) NOT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE AuthorizationTreeUpdateData (
    pK INTEGER NOT NULL,
    authorizationTreeUpdateNumber INTEGER NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE CAData (
    cAId INTEGER NOT NULL,
    data TEXT NOT NULL,
    expireTime DECIMAL(18,0) NOT NULL,
    name VARCHAR(255,0),
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    status INTEGER NOT NULL,
    subjectDN VARCHAR(255,0),
    updateTime DECIMAL(18,0) NOT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint VARCHAR(255,0) NOT NULL,
    base64Crl TEXT NOT NULL,
    cAFingerprint VARCHAR(255,0) NOT NULL,
    cRLNumber INTEGER NOT NULL,
    deltaCRLIndicator INTEGER NOT NULL,
    issuerDN VARCHAR(255,0) NOT NULL,
    nextUpdate DECIMAL(18,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    thisUpdate DECIMAL(18,0) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint VARCHAR(255,0) NOT NULL,
    issuerDN VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    serialNumber VARCHAR(255,0) NOT NULL,
    timestamp DECIMAL(18,0) NOT NULL,
    userDataVO TEXT NOT NULL,
    username VARCHAR(255,0) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateData (
    fingerprint VARCHAR(255,0) NOT NULL,
    base64Cert TEXT,
    cAFingerprint VARCHAR(255,0),
    certificateProfileId INTEGER NOT NULL,
    endEntityProfileId INTEGER,
    expireDate DECIMAL(18,0) NOT NULL,
    issuerDN VARCHAR(255,0) NOT NULL,
    revocationDate DECIMAL(18,0) NOT NULL,
    revocationReason INTEGER NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    serialNumber VARCHAR(255,0) NOT NULL,
    status INTEGER NOT NULL,
    subjectDN VARCHAR(255,0) NOT NULL,
    subjectKeyId VARCHAR(255,0),
    tag VARCHAR(255,0),
    type INTEGER NOT NULL,
    updateTime DECIMAL(18,0) NOT NULL,
    username VARCHAR(255,0),
    PRIMARY KEY (fingerprint)
);

CREATE TABLE Base64CertData (
    fingerprint VARCHAR(255,0) NOT NULL,
    base64Cert TEXT,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateProfileData (
    id INTEGER NOT NULL,
    certificateProfileName VARCHAR(255,0) NOT NULL,
    data BLOB NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE CryptoTokenData (
    id INTEGER NOT NULL,
    lastUpdate DECIMAL(18,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    tokenData TEXT,
    tokenName VARCHAR(255,0) NOT NULL,
    tokenProps TEXT,
    tokenType VARCHAR(255,0) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id INTEGER NOT NULL,
    data BLOB NOT NULL,
    profileName VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE InternalKeyBindingData (
    id INTEGER NOT NULL,
    name VARCHAR(255,0) NOT NULL,
    status VARCHAR(255,0) NOT NULL,
    keyBindingType VARCHAR(255,0) NOT NULL,
    certificateId VARCHAR(255,0),
    cryptoTokenId INTEGER NOT NULL,
    keyPairAlias VARCHAR(255,0) NOT NULL,
    rawData TEXT,
    lastUpdate DECIMAL(18,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId VARCHAR(255,0) NOT NULL,
    data BLOB NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    tokenSN VARCHAR(255,0) NOT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN VARCHAR(255,0) NOT NULL,
    cTime DECIMAL(18,0) NOT NULL,
    data BLOB,
    mTime DECIMAL(18,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    significantIssuerDN VARCHAR(255,0),
    tokenType INTEGER NOT NULL,
    username VARCHAR(255,0),
    PRIMARY KEY (tokenSN)
);

CREATE TABLE HardTokenIssuerData (
    id INTEGER NOT NULL,
    adminGroupId INTEGER NOT NULL,
    alias VARCHAR(255,0) NOT NULL,
    data BLOB NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id INTEGER NOT NULL,
    data TEXT,
    name VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    updateCounter INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id VARCHAR(255,0) NOT NULL,
    property VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    value VARCHAR(255,0),
    PRIMARY KEY (id,
    property)
);

CREATE TABLE KeyRecoveryData (
    certSN VARCHAR(255,0) NOT NULL,
    issuerDN VARCHAR(255,0) NOT NULL,
    keyData TEXT NOT NULL,
    markedAsRecoverable BOOLEAN NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    username VARCHAR(255,0),
    cryptoTokenId INTEGER NOT NULL,
    keyAlias VARCHAR(255,0),
    publicKeyId VARCHAR(255,0),
    PRIMARY KEY (certSN,
    issuerDN)
);

CREATE TABLE PeerData (
    id INTEGER NOT NULL,
    name VARCHAR(255,0) NOT NULL,
    connectorState INTEGER NOT NULL,
    url VARCHAR(255,0) NOT NULL,
    data TEXT,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherData (
    id INTEGER NOT NULL,
    data TEXT,
    name VARCHAR(255,0),
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    updateCounter INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherQueueData (
    pk VARCHAR(255,0) NOT NULL,
    fingerprint VARCHAR(255,0),
    lastUpdate DECIMAL(18,0) NOT NULL,
    publishStatus INTEGER NOT NULL,
    publishType INTEGER NOT NULL,
    publisherId INTEGER NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    timeCreated DECIMAL(18,0) NOT NULL,
    tryCounter INTEGER NOT NULL,
    volatileData TEXT,
    PRIMARY KEY (pk)
);

CREATE TABLE ServiceData (
    id INTEGER NOT NULL,
    data TEXT,
    name VARCHAR(255,0) NOT NULL,
    nextRunTimeStamp DECIMAL(18,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    runTimeStamp DECIMAL(18,0) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE UserData (
    username VARCHAR(255,0) NOT NULL,
    cAId INTEGER NOT NULL,
    cardNumber VARCHAR(255,0),
    certificateProfileId INTEGER NOT NULL,
    clearPassword VARCHAR(255,0),
    endEntityProfileId INTEGER NOT NULL,
    extendedInformationData TEXT,
    hardTokenIssuerId INTEGER NOT NULL,
    keyStorePassword VARCHAR(255,0),
    passwordHash VARCHAR(255,0),
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    status INTEGER NOT NULL,
    subjectAltName VARCHAR(255,0),
    subjectDN VARCHAR(255,0),
    subjectEmail VARCHAR(255,0),
    timeCreated DECIMAL(18,0) NOT NULL,
    timeModified DECIMAL(18,0) NOT NULL,
    tokenType INTEGER NOT NULL,
    type INTEGER NOT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id INTEGER NOT NULL,
    data TEXT,
    name VARCHAR(255,0) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    updateCounter INTEGER NOT NULL,
    PRIMARY KEY (id)
);

alter table AccessRulesData add constraint  foreign key (AdminGroupData_accessRules) references AdminGroupData constraint FKABB4C1DFDBBC970;

alter table AdminEntityData add constraint  foreign key (AdminGroupData_adminEntities) references AdminGroupData constraint FKD9A99EBCB3A110AD;


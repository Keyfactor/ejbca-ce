CREATE TABLE AccessRulesData (
    pK INTEGER NOT NULL,
    accessRule VARCHAR(255) NOT NULL,
    isRecursive BIT NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    rule_ INTEGER NOT NULL,
    AdminGroupData_accessRules INTEGER null,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminEntityData (
    pK INTEGER NOT NULL,
    cAId INTEGER NOT NULL,
    matchType INTEGER NOT NULL,
    matchValue VARCHAR(255) null,
    matchWith INTEGER NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    AdminGroupData_adminEntities INTEGER null,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK INTEGER NOT NULL,
    adminGroupName VARCHAR(255) NOT NULL,
    cAId INTEGER NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminPreferencesData (
    id VARCHAR(255) NOT NULL,
    data IMAGE NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ApprovalData (
    id INTEGER NOT NULL,
    approvalData TEXT NOT NULL,
    approvalId INTEGER NOT NULL,
    approvalType INTEGER NOT NULL,
    cAId INTEGER NOT NULL,
    endEntityProfileId INTEGER NOT NULL,
    expireDate DECIMAL(20,0) NOT NULL,
    remainingApprovals INTEGER NOT NULL,
    reqAdminCertIssuerDn VARCHAR(255) null,
    reqAdminCertSn VARCHAR(255) null,
    requestData TEXT NOT NULL,
    requestDate DECIMAL(20,0) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    status INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE AuthorizationTreeUpdateData (
    pK INTEGER NOT NULL,
    authorizationTreeUpdateNumber INTEGER NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE CAData (
    cAId INTEGER NOT NULL,
    data TEXT NOT NULL,
    expireTime DECIMAL(20,0) NOT NULL,
    name VARCHAR(255) null,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    status INTEGER NOT NULL,
    subjectDN VARCHAR(255) null,
    updateTime DECIMAL(20,0) NOT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint VARCHAR(255) NOT NULL,
    base64Crl TEXT NOT NULL,
    cAFingerprint VARCHAR(255) NOT NULL,
    cRLNumber INTEGER NOT NULL,
    deltaCRLIndicator INTEGER NOT NULL,
    issuerDN VARCHAR(255) NOT NULL,
    nextUpdate DECIMAL(20,0) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    thisUpdate DECIMAL(20,0) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint VARCHAR(255) NOT NULL,
    issuerDN VARCHAR(255) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    serialNumber VARCHAR(255) NOT NULL,
    timestamp DECIMAL(20,0) NOT NULL,
    userDataVO TEXT NOT NULL,
    username VARCHAR(255) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateData (
    fingerprint VARCHAR(255) NOT NULL,
    base64Cert TEXT null,
    cAFingerprint VARCHAR(255) null,
    certificateProfileId INTEGER NOT NULL,
    expireDate DECIMAL(20,0) NOT NULL,
    issuerDN VARCHAR(255) NOT NULL,
    revocationDate DECIMAL(20,0) NOT NULL,
    revocationReason INTEGER NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    serialNumber VARCHAR(255) NOT NULL,
    status INTEGER NOT NULL,
    subjectDN VARCHAR(255) NOT NULL,
    subjectKeyId VARCHAR(255) null,
    tag VARCHAR(255) null,
    type INTEGER NOT NULL,
    updateTime DECIMAL(20,0) NOT NULL,
    username VARCHAR(255) null,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateProfileData (
    id INTEGER NOT NULL,
    certificateProfileName VARCHAR(255) NOT NULL,
    data IMAGE NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id INTEGER NOT NULL,
    data IMAGE NOT NULL,
    profileName VARCHAR(255) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId VARCHAR(255) NOT NULL,
    data IMAGE NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint VARCHAR(255) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    tokenSN VARCHAR(255) NOT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN VARCHAR(255) NOT NULL,
    cTime DECIMAL(20,0) NOT NULL,
    data IMAGE null,
    mTime DECIMAL(20,0) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    significantIssuerDN VARCHAR(255) null,
    tokenType INTEGER NOT NULL,
    username VARCHAR(255) null,
    PRIMARY KEY (tokenSN)
);

CREATE TABLE HardTokenIssuerData (
    id INTEGER NOT NULL,
    adminGroupId INTEGER NOT NULL,
    alias VARCHAR(255) NOT NULL,
    data IMAGE NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id INTEGER NOT NULL,
    data TEXT null,
    name VARCHAR(255) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    updateCounter INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id VARCHAR(255) NOT NULL,
    property VARCHAR(255) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    value VARCHAR(255) null,
    PRIMARY KEY (id,
    property)
);

CREATE TABLE KeyRecoveryData (
    certSN VARCHAR(255) NOT NULL,
    issuerDN VARCHAR(255) NOT NULL,
    keyData TEXT NOT NULL,
    markedAsRecoverable BIT NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    username VARCHAR(255) null,
    PRIMARY KEY (certSN,
    issuerDN)
);

CREATE TABLE LogConfigurationData (
    id INTEGER NOT NULL,
    logConfiguration IMAGE NOT NULL,
    logEntryRowNumber INTEGER NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE LogEntryData (
    id INTEGER NOT NULL,
    adminData VARCHAR(255) null,
    adminType INTEGER NOT NULL,
    caId INTEGER NOT NULL,
    certificateSNR VARCHAR(255) null,
    event INTEGER NOT NULL,
    logComment VARCHAR(255) null,
    module INTEGER NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    time DECIMAL(20,0) NOT NULL,
    username VARCHAR(255) null,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherData (
    id INTEGER NOT NULL,
    data TEXT null,
    name VARCHAR(255) null,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    updateCounter INTEGER NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherQueueData (
    pk VARCHAR(255) NOT NULL,
    fingerprint VARCHAR(255) null,
    lastUpdate DECIMAL(20,0) NOT NULL,
    publishStatus INTEGER NOT NULL,
    publishType INTEGER NOT NULL,
    publisherId INTEGER NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    timeCreated DECIMAL(20,0) NOT NULL,
    tryCounter INTEGER NOT NULL,
    volatileData TEXT null,
    PRIMARY KEY (pk)
);

CREATE TABLE ServiceData (
    id INTEGER NOT NULL,
    data TEXT null,
    name VARCHAR(255) NOT NULL,
    nextRunTimeStamp DECIMAL(20,0) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    runTimeStamp DECIMAL(20,0) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE UserData (
    username VARCHAR(255) NOT NULL,
    cAId INTEGER NOT NULL,
    cardNumber VARCHAR(255) null,
    certificateProfileId INTEGER NOT NULL,
    clearPassword VARCHAR(255) null,
    endEntityProfileId INTEGER NOT NULL,
    extendedInformationData TEXT null,
    hardTokenIssuerId INTEGER NOT NULL,
    keyStorePassword VARCHAR(255) null,
    passwordHash VARCHAR(255) null,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    status INTEGER NOT NULL,
    subjectAltName VARCHAR(255) null,
    subjectDN VARCHAR(255) null,
    subjectEmail VARCHAR(255) null,
    timeCreated DECIMAL(20,0) NOT NULL,
    timeModified DECIMAL(20,0) NOT NULL,
    tokenType INTEGER NOT NULL,
    type INTEGER NOT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id INTEGER NOT NULL,
    data TEXT null,
    name VARCHAR(255) NOT NULL,
    rowProtection TEXT null,
    rowVersion INTEGER NOT NULL,
    updateCounter INTEGER NOT NULL,
    PRIMARY KEY (id)
);

alter table AccessRulesData add constraint FKABB4C1DFD8AEA20 foreign key (AdminGroupData_accessRules) references AdminGroupData;

alter table AdminEntityData add constraint FKD9A99EBCB370315D foreign key (AdminGroupData_adminEntities) references AdminGroupData;


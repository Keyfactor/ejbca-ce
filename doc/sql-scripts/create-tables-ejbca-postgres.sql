CREATE TABLE AccessRulesData (
    pK INT4 NOT NULL,
    accessRule TEXT NOT NULL,
    isRecursive BOOLEAN NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    rule INT4 NOT NULL,
    AdminGroupData_accessRules INT4,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminEntityData (
    pK INT4 NOT NULL,
    cAId INT4 NOT NULL,
    matchType INT4 NOT NULL,
    matchValue TEXT,
    matchWith INT4 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    tokenType TEXT,
    AdminGroupData_adminEntities INT4,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK INT4 NOT NULL,
    adminGroupName TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminPreferencesData (
    id TEXT NOT NULL,
    data BYTEA NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ApprovalData (
    id INT4 NOT NULL,
    approvalData TEXT NOT NULL,
    approvalId INT4 NOT NULL,
    approvalType INT4 NOT NULL,
    cAId INT4 NOT NULL,
    endEntityProfileId INT4 NOT NULL,
    expireDate INT8 NOT NULL,
    remainingApprovals INT4 NOT NULL,
    reqAdminCertIssuerDn TEXT,
    reqAdminCertSn TEXT,
    requestData TEXT NOT NULL,
    requestDate INT8 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE AuditRecordData (
    pk TEXT NOT NULL,
    additionalDetails TEXT,
    authToken TEXT NOT NULL,
    customId TEXT,
    eventStatus TEXT NOT NULL,
    eventType TEXT NOT NULL,
    module TEXT NOT NULL,
    nodeId TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    searchDetail1 TEXT,
    searchDetail2 TEXT,
    sequenceNumber INT8 NOT NULL,
    service TEXT NOT NULL,
    timeStamp INT8 NOT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE AuthorizationTreeUpdateData (
    pK INT4 NOT NULL,
    authorizationTreeUpdateNumber INT4 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE CAData (
    cAId INT4 NOT NULL,
    data TEXT NOT NULL,
    expireTime INT8 NOT NULL,
    name TEXT,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    subjectDN TEXT,
    updateTime INT8 NOT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint TEXT NOT NULL,
    base64Crl TEXT NOT NULL,
    cAFingerprint TEXT NOT NULL,
    cRLNumber INT4 NOT NULL,
    deltaCRLIndicator INT4 NOT NULL,
    issuerDN TEXT NOT NULL,
    nextUpdate INT8 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    thisUpdate INT8 NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint TEXT NOT NULL,
    issuerDN TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    serialNumber TEXT NOT NULL,
    timestamp INT8 NOT NULL,
    userDataVO TEXT NOT NULL,
    username TEXT NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateData (
    fingerprint TEXT NOT NULL,
    base64Cert TEXT,
    cAFingerprint TEXT,
    certificateProfileId INT4 NOT NULL,
    expireDate INT8 NOT NULL,
    issuerDN TEXT NOT NULL,
    revocationDate INT8 NOT NULL,
    revocationReason INT4 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    serialNumber TEXT NOT NULL,
    status INT4 NOT NULL,
    subjectDN TEXT NOT NULL,
    subjectKeyId TEXT,
    tag TEXT,
    type INT4 NOT NULL,
    updateTime INT8 NOT NULL,
    username TEXT,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE Base64CertData (
    fingerprint TEXT NOT NULL,
    base64Cert TEXT,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateProfileData (
    id INT4 NOT NULL,
    certificateProfileName TEXT NOT NULL,
    data BYTEA NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE CryptoTokenData (
    id INT4 NOT NULL,
    lastUpdate INT8 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    tokenData TEXT,
    tokenName TEXT NOT NULL,
    tokenProps TEXT,
    tokenType TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id INT4 NOT NULL,
    data BYTEA NOT NULL,
    profileName TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE InternalKeyBindingData (
    id INT4 NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    keyBindingType TEXT NOT NULL,
    certificateId TEXT,
    cryptoTokenId INT4 NOT NULL,
    keyPairAlias TEXT NOT NULL,
    rawData TEXT,
    lastUpdate INT8 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId TEXT NOT NULL,
    data BYTEA NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    tokenSN TEXT NOT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN TEXT NOT NULL,
    cTime INT8 NOT NULL,
    data BYTEA,
    mTime INT8 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    significantIssuerDN TEXT,
    tokenType INT4 NOT NULL,
    username TEXT,
    PRIMARY KEY (tokenSN)
);

CREATE TABLE HardTokenIssuerData (
    id INT4 NOT NULL,
    adminGroupId INT4 NOT NULL,
    alias TEXT NOT NULL,
    data BYTEA NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id INT4 NOT NULL,
    data TEXT,
    name TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id TEXT NOT NULL,
    property TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    value TEXT,
    PRIMARY KEY (id,
    property)
);

CREATE TABLE KeyRecoveryData (
    certSN TEXT NOT NULL,
    issuerDN TEXT NOT NULL,
    keyData TEXT NOT NULL,
    markedAsRecoverable BOOLEAN NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    username TEXT,
    cryptoTokenId INT4 NOT NULL,
    keyAlias TEXT,
    publicKeyId TEXT,
    PRIMARY KEY (certSN,
    issuerDN)
);

CREATE TABLE PeerData (
    id INT4 NOT NULL,
    name TEXT NOT NULL,
    connectorState INT4 NOT NULL,
    url TEXT NOT NULL,
    data TEXT,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherData (
    id INT4 NOT NULL,
    data TEXT,
    name TEXT,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherQueueData (
    pk TEXT NOT NULL,
    fingerprint TEXT,
    lastUpdate INT8 NOT NULL,
    publishStatus INT4 NOT NULL,
    publishType INT4 NOT NULL,
    publisherId INT4 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    timeCreated INT8 NOT NULL,
    tryCounter INT4 NOT NULL,
    volatileData TEXT,
    PRIMARY KEY (pk)
);

CREATE TABLE ServiceData (
    id INT4 NOT NULL,
    data TEXT,
    name TEXT NOT NULL,
    nextRunTimeStamp INT8 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    runTimeStamp INT8 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE UserData (
    username TEXT NOT NULL,
    cAId INT4 NOT NULL,
    cardNumber TEXT,
    certificateProfileId INT4 NOT NULL,
    clearPassword TEXT,
    endEntityProfileId INT4 NOT NULL,
    extendedInformationData TEXT,
    hardTokenIssuerId INT4 NOT NULL,
    keyStorePassword TEXT,
    passwordHash TEXT,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    subjectAltName TEXT,
    subjectDN TEXT,
    subjectEmail TEXT,
    timeCreated INT8 NOT NULL,
    timeModified INT8 NOT NULL,
    tokenType INT4 NOT NULL,
    type INT4 NOT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id INT4 NOT NULL,
    data TEXT,
    name TEXT NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

alter table AccessRulesData add constraint FKABB4C1DFDBBC970 foreign key (AdminGroupData_accessRules) references AdminGroupData;

alter table AdminEntityData add constraint FKD9A99EBCB3A110AD foreign key (AdminGroupData_adminEntities) references AdminGroupData;


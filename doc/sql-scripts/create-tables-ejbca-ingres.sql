CREATE TABLE AccessRulesData (
    pK INT4 NOT NULL,
    accessRule VARCHAR(256) NOT NULL,
    isRecursive INT4 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    rule INT4 NOT NULL,
    AdminGroupData_accessRules INT4 with null,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminEntityData (
    pK INT4 NOT NULL,
    cAId INT4 NOT NULL,
    matchType INT4 NOT NULL,
    matchValue VARCHAR(256) with null,
    matchWith INT4 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    tokenType VARCHAR(256) with null,
    AdminGroupData_adminEntities INT4 with null,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK INT4 NOT NULL,
    adminGroupName VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminPreferencesData (
    id VARCHAR(256) NOT NULL,
    data LONG BYTE NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ApprovalData (
    id INT4 NOT NULL,
    approvalData LONG VARCHAR NOT NULL,
    approvalId INT4 NOT NULL,
    approvalType INT4 NOT NULL,
    cAId INT4 NOT NULL,
    endEntityProfileId INT4 NOT NULL,
    expireDate INT8 NOT NULL,
    remainingApprovals INT4 NOT NULL,
    reqAdminCertIssuerDn VARCHAR(256) with null,
    reqAdminCertSn VARCHAR(256) with null,
    requestData LONG VARCHAR NOT NULL,
    requestDate INT8 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE AuditRecordData (
    pk VARCHAR(256) NOT NULL,
    additionalDetails LONG VARCHAR with null,
    authToken VARCHAR(256) NOT NULL,
    customId VARCHAR(256) with null,
    eventStatus VARCHAR(256) NOT NULL,
    eventType VARCHAR(256) NOT NULL,
    module VARCHAR(256) NOT NULL,
    nodeId VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    searchDetail1 VARCHAR(256) with null,
    searchDetail2 VARCHAR(256) with null,
    sequenceNumber INT8 NOT NULL,
    service VARCHAR(256) NOT NULL,
    timeStamp INT8 NOT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE AuthorizationTreeUpdateData (
    pK INT4 NOT NULL,
    authorizationTreeUpdateNumber INT4 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE Base64CertData (
    fingerprint VARCHAR(256) NOT NULL,
    base64Cert LONG VARCHAR with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CAData (
    cAId INT4 NOT NULL,
    data LONG VARCHAR NOT NULL,
    expireTime INT8 NOT NULL,
    name VARCHAR(256) with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    subjectDN VARCHAR(256) with null,
    updateTime INT8 NOT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint VARCHAR(256) NOT NULL,
    base64Crl LONG VARCHAR NOT NULL,
    cAFingerprint VARCHAR(256) NOT NULL,
    cRLNumber INT4 NOT NULL,
    deltaCRLIndicator INT4 NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    nextUpdate INT8 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    thisUpdate INT8 NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint VARCHAR(256) NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    serialNumber VARCHAR(256) NOT NULL,
    timestamp INT8 NOT NULL,
    userDataVO LONG VARCHAR NOT NULL,
    username VARCHAR(256) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateData (
    fingerprint VARCHAR(256) NOT NULL,
    base64Cert LONG VARCHAR with null,
    cAFingerprint VARCHAR(256) with null,
    certificateProfileId INT4 NOT NULL,
    endEntityProfileId INT4 with null,
    expireDate INT8 NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    notBefore INT8 with null,
    revocationDate INT8 NOT NULL,
    revocationReason INT4 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    serialNumber VARCHAR(256) NOT NULL,
    status INT4 NOT NULL,
    subjectAltName VARCHAR(2000) with null,
    subjectDN VARCHAR(400) NOT NULL,
    subjectKeyId VARCHAR(256) with null,
    tag VARCHAR(256) with null,
    type INT4 NOT NULL,
    updateTime INT8 NOT NULL,
    username VARCHAR(256) with null,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateProfileData (
    id INT4 NOT NULL,
    certificateProfileName VARCHAR(256) NOT NULL,
    data LONG BYTE NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE CryptoTokenData (
    id INT4 NOT NULL,
    lastUpdate BIGINT NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    tokenData LONG VARCHAR with null,
    tokenName VARCHAR(256) NOT NULL,
    tokenProps LONG VARCHAR with null,
    tokenType VARCHAR(256) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id INT4 NOT NULL,
    data LONG BYTE NOT NULL,
    profileName VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId VARCHAR(256) NOT NULL,
    data LONG BYTE NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    tokenSN VARCHAR(256) NOT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN VARCHAR(256) NOT NULL,
    cTime INT8 NOT NULL,
    data LONG BYTE with null,
    mTime INT8 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    significantIssuerDN VARCHAR(256) with null,
    tokenType INT4 NOT NULL,
    username VARCHAR(256) with null,
    PRIMARY KEY (tokenSN)
);

CREATE TABLE HardTokenIssuerData (
    id INT4 NOT NULL,
    adminGroupId INT4 NOT NULL,
    alias VARCHAR(256) NOT NULL,
    data LONG BYTE NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id INT4 NOT NULL,
    data LONG VARCHAR with null,
    name VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id VARCHAR(256) NOT NULL,
    property VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    value VARCHAR(256) with null,
    PRIMARY KEY (id,
    property)
);

CREATE TABLE InternalKeyBindingData (
    id INT4 NOT NULL,
    certificateId VARCHAR(256) with null,
    cryptoTokenId INT4 NOT NULL,
    keyBindingType VARCHAR(256) NOT NULL,
    keyPairAlias VARCHAR(256) NOT NULL,
    lastUpdate INT8 NOT NULL,
    name VARCHAR(256) NOT NULL,
    rawData LONG VARCHAR with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    status VARCHAR(256) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE KeyRecoveryData (
    certSN VARCHAR(256) NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    cryptoTokenId INT4 NOT NULL,
    keyAlias VARCHAR(256) with null,
    keyData LONG VARCHAR NOT NULL,
    markedAsRecoverable INT4 NOT NULL,
    publicKeyId VARCHAR(256) with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    username VARCHAR(256) with null,
    PRIMARY KEY (certSN,
    issuerDN)
);

CREATE TABLE PeerData (
    id INT4 NOT NULL,
    connectorState INT4 NOT NULL,
    data LONG VARCHAR with null,
    name VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    url VARCHAR(256) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ProfileData (
    id INT4 NOT NULL,
    profileName VARCHAR(256) NOT NULL,
    profileType VARCHAR(256) NOT NULL,
    rawData LONG VARCHAR with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherData (
    id INT4 NOT NULL,
    data LONG VARCHAR with null,
    name VARCHAR(256) with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherQueueData (
    pk VARCHAR(256) NOT NULL,
    fingerprint VARCHAR(256) with null,
    lastUpdate INT8 NOT NULL,
    publishStatus INT4 NOT NULL,
    publishType INT4 NOT NULL,
    publisherId INT4 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    timeCreated INT8 NOT NULL,
    tryCounter INT4 NOT NULL,
    volatileData LONG VARCHAR with null,
    PRIMARY KEY (pk)
);

CREATE TABLE RoleData (
    id INT4 NOT NULL,
    roleName VARCHAR(256) NOT NULL,
    nameSpace VARCHAR(256) with null,
    rawData LONG VARCHAR with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE RoleMemberData (
	primaryKey INT4  NOT NULL,
	tokenSubType INT4  NOT NULL,
	tokenType VARCHAR(256) NOT NULL,
	tokenMatchValue VARCHAR(256) NOT NULL,
	roleId INT4,
	memberBindingType VARCHAR(256),
	memberBindingValue VARCHAR(256),
	rowProtection LONG VARCHAR with null,
    rowVersion INT4  NOT NULL,
    PRIMARY KEY (primaryKey)
);

CREATE TABLE ServiceData (
    id INT4 NOT NULL,
    data LONG VARCHAR with null,
    name VARCHAR(256) NOT NULL,
    nextRunTimeStamp INT8 NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    runTimeStamp INT8 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE UserData (
    username VARCHAR(256) NOT NULL,
    cAId INT4 NOT NULL,
    cardNumber VARCHAR(256) with null,
    certificateProfileId INT4 NOT NULL,
    clearPassword VARCHAR(256) with null,
    endEntityProfileId INT4 NOT NULL,
    extendedInformationData LONG VARCHAR with null,
    hardTokenIssuerId INT4 NOT NULL,
    keyStorePassword VARCHAR(256) with null,
    passwordHash VARCHAR(256) with null,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    subjectAltName VARCHAR(2000) with null,
    subjectDN VARCHAR(400) with null,
    subjectEmail VARCHAR(256) with null,
    timeCreated INT8 NOT NULL,
    timeModified INT8 NOT NULL,
    tokenType INT4 NOT NULL,
    type INT4 NOT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id INT4 NOT NULL,
    data LONG VARCHAR with null,
    name VARCHAR(256) NOT NULL,
    rowProtection LONG VARCHAR with null,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

alter table AccessRulesData add constraint FKABB4C1DFDBBC970 foreign key (AdminGroupData_accessRules) references AdminGroupData;

alter table AdminEntityData add constraint FKD9A99EBCB3A110AD foreign key (AdminGroupData_adminEntities) references AdminGroupData;


CREATE TABLE AccessRulesData (
    pK INT(11) NOT NULL,
    accessRule VARCHAR(250) BINARY NOT NULL,
    isRecursive TINYINT(4) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    rule INT(11) NOT NULL,
    AdminGroupData_accessRules INT(11),
    PRIMARY KEY (pK)
);

CREATE TABLE AdminEntityData (
    pK INT(11) NOT NULL,
    cAId INT(11) NOT NULL,
    matchType INT(11) NOT NULL,
    matchValue VARCHAR(250) BINARY,
    matchWith INT(11) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    tokenType VARCHAR(250) BINARY,
    AdminGroupData_adminEntities INT(11),
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK INT(11) NOT NULL,
    adminGroupName VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminPreferencesData (
    id VARCHAR(250) BINARY NOT NULL,
    data LONGBLOB NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ApprovalData (
    id INT(11) NOT NULL,
    approvalData LONGTEXT NOT NULL,
    approvalId INT(11) NOT NULL,
    approvalType INT(11) NOT NULL,
    cAId INT(11) NOT NULL,
    endEntityProfileId INT(11) NOT NULL,
    expireDate BIGINT(20) NOT NULL,
    remainingApprovals INT(11) NOT NULL,
    reqAdminCertIssuerDn VARCHAR(250) BINARY,
    reqAdminCertSn VARCHAR(250) BINARY,
    requestData LONGTEXT NOT NULL,
    requestDate BIGINT(20) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    status INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE AuditRecordData (
    pk VARCHAR(250) BINARY NOT NULL,
    additionalDetails LONGTEXT,
    authToken VARCHAR(250) BINARY NOT NULL,
    customId VARCHAR(250) BINARY,
    eventStatus VARCHAR(250) BINARY NOT NULL,
    eventType VARCHAR(250) BINARY NOT NULL,
    module VARCHAR(250) BINARY NOT NULL,
    nodeId VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    searchDetail1 VARCHAR(250) BINARY,
    searchDetail2 VARCHAR(250) BINARY,
    sequenceNumber BIGINT(20) NOT NULL,
    service VARCHAR(250) BINARY NOT NULL,
    timeStamp BIGINT(20) NOT NULL,
    PRIMARY KEY (pk)
);

CREATE TABLE AuthorizationTreeUpdateData (
    pK INT(11) NOT NULL,
    authorizationTreeUpdateNumber INT(11) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE Base64CertData (
    fingerprint VARCHAR(250) BINARY NOT NULL,
    base64Cert LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CAData (
    cAId INT(11) NOT NULL,
    data LONGTEXT NOT NULL,
    expireTime BIGINT(20) NOT NULL,
    name VARCHAR(250) BINARY,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    status INT(11) NOT NULL,
    subjectDN VARCHAR(250) BINARY,
    updateTime BIGINT(20) NOT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint VARCHAR(250) BINARY NOT NULL,
    base64Crl LONGTEXT NOT NULL,
    cAFingerprint VARCHAR(250) BINARY NOT NULL,
    cRLNumber INT(11) NOT NULL,
    deltaCRLIndicator INT(11) NOT NULL,
    issuerDN VARCHAR(250) BINARY NOT NULL,
    nextUpdate BIGINT(20) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    thisUpdate BIGINT(20) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint VARCHAR(250) BINARY NOT NULL,
    issuerDN VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    serialNumber VARCHAR(250) BINARY NOT NULL,
    timestamp BIGINT(20) NOT NULL,
    userDataVO LONGTEXT NOT NULL,
    username VARCHAR(250) BINARY NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateData (
    fingerprint VARCHAR(250) BINARY NOT NULL,
    base64Cert LONGTEXT,
    cAFingerprint VARCHAR(250) BINARY,
    certificateProfileId INT(11) NOT NULL,
    endEntityProfileId INT(11),
    expireDate BIGINT(20) NOT NULL,
    issuerDN VARCHAR(250) BINARY NOT NULL,
    notBefore BIGINT(20),
    revocationDate BIGINT(20) NOT NULL,
    revocationReason INT(11) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    serialNumber VARCHAR(250) BINARY NOT NULL,
    status INT(11) NOT NULL,
    subjectAltName VARCHAR(2000) BINARY,
    subjectDN VARCHAR(400) BINARY NOT NULL,
    subjectKeyId VARCHAR(250) BINARY,
    tag VARCHAR(250) BINARY,
    type INT(11) NOT NULL,
    updateTime BIGINT(20) NOT NULL,
    username VARCHAR(250) BINARY,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateProfileData (
    id INT(11) NOT NULL,
    certificateProfileName VARCHAR(250) BINARY NOT NULL,
    data LONGBLOB NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE CryptoTokenData (
    id INT(11) NOT NULL,
    lastUpdate BIGINT(20) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    tokenData LONGTEXT,
    tokenName VARCHAR(250) BINARY NOT NULL,
    tokenProps LONGTEXT,
    tokenType VARCHAR(250) BINARY NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id INT(11) NOT NULL,
    data LONGBLOB NOT NULL,
    profileName VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId VARCHAR(250) BINARY NOT NULL,
    data LONGBLOB NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    tokenSN VARCHAR(250) BINARY NOT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN VARCHAR(250) BINARY NOT NULL,
    cTime BIGINT(20) NOT NULL,
    data LONGBLOB,
    mTime BIGINT(20) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    significantIssuerDN VARCHAR(250) BINARY,
    tokenType INT(11) NOT NULL,
    username VARCHAR(250) BINARY,
    PRIMARY KEY (tokenSN)
);

CREATE TABLE HardTokenIssuerData (
    id INT(11) NOT NULL,
    adminGroupId INT(11) NOT NULL,
    alias VARCHAR(250) BINARY NOT NULL,
    data LONGBLOB NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id INT(11) NOT NULL,
    data LONGTEXT,
    name VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    updateCounter INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id VARCHAR(80) BINARY NOT NULL,
    property VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    value VARCHAR(250) BINARY,
    PRIMARY KEY (id,
    property)
);

CREATE TABLE InternalKeyBindingData (
    id INT(11) NOT NULL,
    certificateId VARCHAR(250) BINARY,
    cryptoTokenId INT(11) NOT NULL,
    keyBindingType VARCHAR(250) BINARY NOT NULL,
    keyPairAlias VARCHAR(250) BINARY NOT NULL,
    lastUpdate BIGINT(20) NOT NULL,
    name VARCHAR(250) BINARY NOT NULL,
    rawData LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    status VARCHAR(250) BINARY NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE KeyRecoveryData (
    certSN VARCHAR(80) BINARY NOT NULL,
    issuerDN VARCHAR(250) BINARY NOT NULL,
    cryptoTokenId INT(11) DEFAULT 0 NOT NULL,
    keyAlias VARCHAR(250) BINARY,
    keyData LONGTEXT NOT NULL,
    markedAsRecoverable TINYINT(4) NOT NULL,
    publicKeyId VARCHAR(250) BINARY,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    username VARCHAR(250) BINARY,
    PRIMARY KEY (certSN,
    issuerDN)
);

CREATE TABLE PeerData (
    id INT(11) NOT NULL,
    connectorState INT(11) NOT NULL,
    data LONGTEXT,
    name VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    url VARCHAR(250) BINARY NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ProfileData (
    id INT(11) NOT NULL,
    profileName VARCHAR(250) BINARY NOT NULL,
    profileType VARCHAR(250) BINARY NOT NULL,
    rawData LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherData (
    id INT(11) NOT NULL,
    data LONGTEXT,
    name VARCHAR(250) BINARY,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    updateCounter INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE PublisherQueueData (
    pk VARCHAR(250) BINARY NOT NULL,
    fingerprint VARCHAR(250) BINARY,
    lastUpdate BIGINT(20) NOT NULL,
    publishStatus INT(11) NOT NULL,
    publishType INT(11) NOT NULL,
    publisherId INT(11) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    timeCreated BIGINT(20) NOT NULL,
    tryCounter INT(11) NOT NULL,
    volatileData LONGTEXT,
    PRIMARY KEY (pk)
);

CREATE TABLE BlacklistData (
    id INT(11) NOT NULL,
    type VARCHAR(250) BINARY NOT NULL,
    value VARCHAR(250) BINARY NOT NULL,
    data VARCHAR(250) BINARY,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    updateCounter INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE RoleData (
    id INT(11) NOT NULL,
    roleName VARCHAR(250) BINARY NOT NULL,
    nameSpace VARCHAR(250) BINARY,
    rawData LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE RoleMemberData (
    primaryKey INT(11) NOT NULL,
    tokenType VARCHAR(250) BINARY NOT NULL,
    tokenIssuerId INT(11) NOT NULL,
    tokenMatchKey INT(11) NOT NULL,
    tokenMatchOperator INT(11) NOT NULL,
    tokenMatchValue VARCHAR(2000) BINARY,
    roleId INT(11) NOT NULL,
    description VARCHAR(250) BINARY,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (primaryKey)
);

CREATE TABLE ServiceData (
    id INT(11) NOT NULL,
    data LONGTEXT,
    name VARCHAR(250) BINARY NOT NULL,
    nextRunTimeStamp BIGINT(20) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    runTimeStamp BIGINT(20) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE UserData (
    username VARCHAR(250) BINARY NOT NULL,
    cAId INT(11) NOT NULL,
    cardNumber VARCHAR(250) BINARY,
    certificateProfileId INT(11) NOT NULL,
    clearPassword VARCHAR(250) BINARY,
    endEntityProfileId INT(11) NOT NULL,
    extendedInformationData LONGTEXT,
    hardTokenIssuerId INT(11) NOT NULL,
    keyStorePassword VARCHAR(250) BINARY,
    passwordHash VARCHAR(250) BINARY,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    status INT(11) NOT NULL,
    subjectAltName VARCHAR(2000) BINARY,
    subjectDN VARCHAR(400) BINARY,
    subjectEmail VARCHAR(250) BINARY,
    timeCreated BIGINT(20) NOT NULL,
    timeModified BIGINT(20) NOT NULL,
    tokenType INT(11) NOT NULL,
    type INT(11) NOT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id INT(11) NOT NULL,
    data LONGTEXT,
    name VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    updateCounter INT(11) NOT NULL,
    PRIMARY KEY (id)
);


alter table AccessRulesData add index FKABB4C1DFDBBC970 (AdminGroupData_accessRules), add constraint FKABB4C1DFDBBC970 foreign key (AdminGroupData_accessRules) references AdminGroupData (pK);

alter table AdminEntityData add index FKD9A99EBCB3A110AD (AdminGroupData_adminEntities), add constraint FKD9A99EBCB3A110AD foreign key (AdminGroupData_adminEntities) references AdminGroupData (pK);

CREATE TABLE NoConflictCertificateData (
    id VARCHAR(250) BINARY NOT NULL,
    fingerprint VARCHAR(250) BINARY NOT NULL,
    base64Cert LONGTEXT,
    cAFingerprint VARCHAR(250) BINARY,
    certificateProfileId INT(11) NOT NULL,
    endEntityProfileId INT(11),
    expireDate BIGINT(20) NOT NULL,
    issuerDN VARCHAR(250) BINARY NOT NULL,
    notBefore BIGINT(20),
    revocationDate BIGINT(20) NOT NULL,
    revocationReason INT(11) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    serialNumber VARCHAR(250) BINARY NOT NULL,
    status INT(11) NOT NULL,
    subjectAltName VARCHAR(2000) BINARY,
    subjectDN VARCHAR(400) BINARY NOT NULL,
    subjectKeyId VARCHAR(250) BINARY,
    tag VARCHAR(250) BINARY,
    type INT(11) NOT NULL,
    updateTime BIGINT(20) NOT NULL,
    username VARCHAR(250) BINARY,
    PRIMARY KEY (id)
);

CREATE TABLE AcmeNonceData (
    nonce VARCHAR(250) BINARY NOT NULL,
    timeExpires BIGINT(20) NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (nonce)
);

CREATE TABLE AcmeAccountData (
    accountId VARCHAR(250) BINARY NOT NULL,
    currentKeyId VARCHAR(250) BINARY NOT NULL,
    rawData LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (accountId)
);

CREATE TABLE AcmeChallengeData (
    challengeId VARCHAR(250) BINARY NOT NULL,
    authorizationId VARCHAR(250) BINARY NOT NULL,
    type VARCHAR(20) BINARY NOT NULL,
    rawData LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (challengeId)
);

CREATE TABLE AcmeOrderData (
    orderId VARCHAR(250) BINARY NOT NULL,
    accountId VARCHAR(250) BINARY NOT NULL,
    fingerprint VARCHAR(250) BINARY,
    status VARCHAR(250) BINARY NOT NULL,
    rawData LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (orderId)
);

CREATE TABLE AcmeAuthorizationData (
    authorizationId VARCHAR(250) BINARY NOT NULL,
    orderId VARCHAR(250) BINARY,
    accountId VARCHAR(250) BINARY NOT NULL,
    rawData LONGTEXT,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (authorizationId)
);

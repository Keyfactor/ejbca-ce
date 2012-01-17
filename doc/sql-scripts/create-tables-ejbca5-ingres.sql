CREATE TABLE AccessRulesData (
    pK INT4 NOT NULL,
    accessRule VARCHAR(256) NOT NULL,
    isRecursive INT4 NOT NULL,
    rowProtection CLOB with null,
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
    tokenType VARCHAR(256) with null,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    AdminGroupData_adminEntities INT4 with null,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK INT4 NOT NULL,
    adminGroupName VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE AdminPreferencesData (
    id VARCHAR(256) NOT NULL,
    data BLOB NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE ApprovalData (
    id INT4 NOT NULL,
    approvalData CLOB NOT NULL,
    approvalId INT4 NOT NULL,
    approvalType INT4 NOT NULL,
    cAId INT4 NOT NULL,
    endEntityProfileId INT4 NOT NULL,
    expireDate INT8 NOT NULL,
    remainingApprovals INT4 NOT NULL,
    reqAdminCertIssuerDn VARCHAR(256) with null,
    reqAdminCertSn VARCHAR(256) with null,
    requestData CLOB NOT NULL,
    requestDate INT8 NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE AuditRecordData (
    pk VARCHAR(256) NOT NULL,
    additionalDetails CLOB with null,
    authToken VARCHAR(256) NOT NULL,
    customId VARCHAR(256) with null,
    eventStatus VARCHAR(256) NOT NULL,
    eventType VARCHAR(256) NOT NULL,
    module VARCHAR(256) NOT NULL,
    nodeId VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
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
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (pK)
);

CREATE TABLE CAData (
    cAId INT4 NOT NULL,
    data CLOB NOT NULL,
    expireTime INT8 NOT NULL,
    name VARCHAR(256) with null,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    subjectDN VARCHAR(256) with null,
    updateTime INT8 NOT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CRLData (
    fingerprint VARCHAR(256) NOT NULL,
    base64Crl CLOB NOT NULL,
    cAFingerprint VARCHAR(256) NOT NULL,
    cRLNumber INT4 NOT NULL,
    deltaCRLIndicator INT4 NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    nextUpdate INT8 NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    thisUpdate INT8 NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertReqHistoryData (
    fingerprint VARCHAR(256) NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    serialNumber VARCHAR(256) NOT NULL,
    timestamp INT8 NOT NULL,
    userDataVO CLOB NOT NULL,
    username VARCHAR(256) NOT NULL,
    PRIMARY KEY (fingerprint)
);

CREATE TABLE CertificateData (
    fingerprint VARCHAR(256) NOT NULL,
    base64Cert CLOB with null,
    cAFingerprint VARCHAR(256) with null,
    certificateProfileId INT4 NOT NULL,
    expireDate INT8 NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    revocationDate INT8 NOT NULL,
    revocationReason INT4 NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    serialNumber VARCHAR(256) NOT NULL,
    status INT4 NOT NULL,
    subjectDN VARCHAR(256) NOT NULL,
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
    data BLOB NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE EndEntityProfileData (
    id INT4 NOT NULL,
    data BLOB NOT NULL,
    profileName VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE GlobalConfigurationData (
    configurationId VARCHAR(256) NOT NULL,
    data BLOB NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (configurationId)
);

CREATE TABLE HardTokenCertificateMap (
    certificateFingerprint VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    tokenSN VARCHAR(256) NOT NULL,
    PRIMARY KEY (certificateFingerprint)
);

CREATE TABLE HardTokenData (
    tokenSN VARCHAR(256) NOT NULL,
    cTime INT8 NOT NULL,
    data BLOB with null,
    mTime INT8 NOT NULL,
    rowProtection CLOB with null,
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
    data BLOB NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenProfileData (
    id INT4 NOT NULL,
    data CLOB with null,
    name VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE HardTokenPropertyData (
    id VARCHAR(256) NOT NULL,
    property VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    value VARCHAR(256) with null,
    PRIMARY KEY (id,
    property)
);

CREATE TABLE KeyRecoveryData (
    certSN VARCHAR(256) NOT NULL,
    issuerDN VARCHAR(256) NOT NULL,
    keyData CLOB NOT NULL,
    markedAsRecoverable INT4 NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    username VARCHAR(256) with null,
    PRIMARY KEY (certSN,
    issuerDN)
);

CREATE TABLE PublisherData (
    id INT4 NOT NULL,
    data CLOB with null,
    name VARCHAR(256) with null,
    rowProtection CLOB with null,
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
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    timeCreated INT8 NOT NULL,
    tryCounter INT4 NOT NULL,
    volatileData CLOB with null,
    PRIMARY KEY (pk)
);

CREATE TABLE ServiceData (
    id INT4 NOT NULL,
    data CLOB with null,
    name VARCHAR(256) NOT NULL,
    nextRunTimeStamp INT8 NOT NULL,
    rowProtection CLOB with null,
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
    extendedInformationData CLOB with null,
    hardTokenIssuerId INT4 NOT NULL,
    keyStorePassword VARCHAR(256) with null,
    passwordHash VARCHAR(256) with null,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    subjectAltName VARCHAR(256) with null,
    subjectDN VARCHAR(256) with null,
    subjectEmail VARCHAR(256) with null,
    timeCreated INT8 NOT NULL,
    timeModified INT8 NOT NULL,
    tokenType INT4 NOT NULL,
    type INT4 NOT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE UserDataSourceData (
    id INT4 NOT NULL,
    data CLOB with null,
    name VARCHAR(256) NOT NULL,
    rowProtection CLOB with null,
    rowVersion INT4 NOT NULL,
    updateCounter INT4 NOT NULL,
    PRIMARY KEY (id)
);

alter table AccessRulesData add constraint FKABB4C1DFD8AEA20 foreign key (AdminGroupData_accessRules) references AdminGroupData;

alter table AdminEntityData add constraint FKD9A99EBCB370315D foreign key (AdminGroupData_adminEntities) references AdminGroupData;


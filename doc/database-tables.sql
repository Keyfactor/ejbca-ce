
CREATE TABLE CertificateData
(
base64Cert       LONG,
fingerprint      VARCHAR2(45)      NOT NULL,
subjectDN        VARCHAR2(256),
issuerDN         VARCHAR2(256),
serialNumber     VARCHAR2(32),
status           INTEGER,
type             INTEGER,
cAFingerprint    VARCHAR(45),
expireDate       NUMBER,
revocationDate   NUMBER,
revocationReason INTEGER,
PRIMARY KEY("FINGERPRINT")
);

CREATE TABLE CRLData
(
base64Crl        LONG,
fingerprint      VARCHAR2(45)      NOT NULL,
issuerDN         VARCHAR2(256),
cRLNumber        VARCHAR2(32),
cAFingerprint    VARCHAR(45),
thisUpdate       NUMBER,
nextUpdate       NUMBER,
PRIMARY KEY("FINGERPRINT")
);

CREATE TABLE UserData
(
username         VARCHAR2(32) NOT NULL,
clearPassword         VARCHAR2(32),
passwordHash     VARCHAR2(64),
subjectDN        VARCHAR2(256),
subjectEmail     VARCHAR2(128),
status           INTEGER,
type             INTEGER,
PRIMARY KEY("USERNAME")
);

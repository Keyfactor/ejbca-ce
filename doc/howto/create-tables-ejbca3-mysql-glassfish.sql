--
-- these definitions should work for ejbca 3.8.x, mysql 4.x or 5.x.
--

drop table if exists accessrulesdata;
create table accessrulesdata (
    pk int(11) not null default '0',
    accessrule varchar(250) binary null default null,
    rule int(11) not null default '0',
    isrecursive tinyint(4) not null default '0',
    `admingroupdata_accessrules` int(11) null default null,
    primary key (pk)
);

drop table if exists adminentitydata;
create table adminentitydata (
    pk int(11) not null default '0',
    matchwith int(11) not null default '0',
    matchtype int(11) not null default '0',
    matchvalue varchar(250) binary null default null,
    `admingroupdata_adminentities` int(11) null default null,
    caid int(11) not null default '0',
    primary key (pk)
);

drop table if exists admingroupdata;
create table admingroupdata (
    pk int(11) not null default '0',
    admingroupname varchar(250) binary null default null,
    caid int(11) not null default '0',
    primary key (pk)
);

drop table if exists adminpreferencesdata;
create table adminpreferencesdata (
    id varchar(250) binary not null default '',
    data longblob null default null,
    primary key (id)
);

drop table if exists approvaldata;
create table approvaldata (
    id int(11) not null default '0',
    approvalid int(11) not null default '0',
    approvaltype int(11) not null default '0',
    endentityprofileid int(11) not null default '0',
    caid int(11) not null default '0',
    reqadmincertissuerdn varchar(250) binary null default null,
    reqadmincertsn varchar(250) binary null default null,
    status int(11) not null default '0',
    approvaldata longtext null default null,
    requestdata longtext null default null,    
    requestdate bigint(20) not null default '0',
    expiredate bigint(20) not null default '0',    
    remainingapprovals int(11) not null default '0',
    primary key (id)
);

drop table if exists authorizationtreeupdatedata;
create table authorizationtreeupdatedata (
    pk int(11) not null default '0',
    authorizationtreeupdatenumber int(11) not null default '0',
    primary key (pk)
);

drop table if exists cadata;
create table cadata (
    caid int(11) not null default '0',
    name varchar(250) binary null default null,
    subjectdn varchar(250) binary null default null,
    status int(11) not null default '0',
    expiretime bigint(20) not null default '0',
    updatetime bigint(20) not null default '0',
    data longtext null default null,
    primary key (caid)
);

drop table if exists crldata;
create table crldata (
    fingerprint varchar(250) binary not null default '',
    crlnumber int(11) not null default '0',
    issuerdn varchar(250) binary null default null,
    cafingerprint varchar(250) binary null default null,
    thisupdate bigint(20) not null default '0',
    nextupdate bigint(20) not null default '0',
    deltacrlindicator int(11) not null default '-1',
    base64crl longtext null default null,
    primary key (fingerprint)
);

drop table if exists certreqhistorydata;
create table certreqhistorydata (
    fingerprint varchar(250) binary not null default '',
    issuerdn varchar(250) binary null default null,
    serialnumber varchar(250) binary null default null,
    `timestamp` bigint(20) not null default '0',
    userdatavo longtext null default null,
    username varchar(250) binary null default null,
    primary key (fingerprint)
);

drop table if exists certificatedata;
create table certificatedata (
    fingerprint varchar(250) binary not null default '',
    issuerdn varchar(250) binary null default null,
    subjectdn varchar(250) binary null default null,
    cafingerprint varchar(250) binary null default null,
    status int(11) not null default '0',
    type int(11) not null default '0',
    serialnumber varchar(250) binary null default null,
    expiredate bigint(20) not null default '0',
    revocationdate bigint(20) not null default '0',
    revocationreason int(11) not null default '0',
    base64cert longtext null default null,
    username varchar(250) binary null default null,
    tag varchar(250) binary null default null,
    certificateprofileid int(11) null default '0',
    updatetime bigint(20) not null default '0',
    subjectkeyid varchar(250) binary null default null,
    primary key (fingerprint)
);

drop table if exists certificateprofiledata;
create table certificateprofiledata (
    id int(11) not null default '0',
    certificateprofilename varchar(250) binary null default null,
    data longblob null default null,
    primary key (id)
);

drop table if exists endentityprofiledata;
create table endentityprofiledata (
    id int(11) not null default '0',
    profilename varchar(250) binary null default null,
    data longblob null default null,
    primary key (id)
);

drop table if exists globalconfigurationdata;
create table globalconfigurationdata (
    configurationid varchar(250) binary not null default '',
    data longblob null default null,
    primary key (configurationid)
);

drop table if exists hardtokencertificatemap;
create table hardtokencertificatemap (
    certificatefingerprint varchar(250) binary not null default '',
    tokensn varchar(250) binary null default null,
    primary key (certificatefingerprint)
);

drop table if exists hardtokendata;
create table hardtokendata (
    tokensn varchar(250) binary not null default '',
    username varchar(250) binary null default null,
    ctime bigint(20) not null default '0',
    mtime bigint(20) not null default '0',
    tokentype int(11) not null default '0',
    significantissuerdn varchar(250) binary null default null,
    data longblob null default null,
    primary key (tokensn)
);

drop table if exists hardtokenissuerdata;
create table hardtokenissuerdata (
    id int(11) not null default '0',
    alias varchar(250) binary null default null,
    admingroupid int(11) not null default '0',
    data longblob null default null,
    primary key (id)
);

drop table if exists hardtokenprofiledata;
create table hardtokenprofiledata (
    id int(11) not null default '0',
    name varchar(250) binary null default null,
    updatecounter int(11) not null default '0',
    data longtext null default null,
    primary key (id)
);

drop table if exists hardtokenpropertydata;
create table hardtokenpropertydata (
    id varchar(250) binary not null default '',
    property varchar(250) binary not null default '',
    value varchar(250) binary null default null,
    primary key (id, property)
);

drop table if exists keyrecoverydata;
create table keyrecoverydata (
    certsn varchar(250) binary not null default '',
    issuerdn varchar(250) binary not null default '',
    username varchar(250) binary null default null,
    markedasrecoverable tinyint(4) not null default '0',
    keydata longtext null default null,
    primary key (certsn, issuerdn)
);

drop table if exists logconfigurationdata;
create table logconfigurationdata (
    id int(11) not null default '0',
    logconfiguration longblob null default null,
    logentryrownumber int(11) not null default '0',
    primary key (id)
);

drop table if exists logentrydata;
create table logentrydata (
    id int(11) not null default '0',
    admintype int(11) not null default '0',
    admindata varchar(250) binary null default null,
    caid int(11) not null default '0',
    module int(11) not null default '0',
    `time` bigint(20) not null default '0',
    username varchar(250) binary null default null,
    certificatesnr varchar(250) binary null default null,
    event int(11) not null default '0',
    logcomment varchar(250) binary null default null,
    primary key (id)
);

drop table if exists publisherdata;
create table publisherdata (
    id int(11) not null default '0',
    name varchar(250) binary null default null,
    updatecounter int(11) not null default '0',
    data longtext null default null,
    primary key (id)
);

drop table if exists publisherqueuedata;
create table publisherqueuedata (
    pk varchar(250) binary not null default '',
    timecreated bigint(20) not null default '0',
    lastupdate bigint(20) not null default '0',
    publishstatus int(11) not null default '0',
    trycounter int(11) not null default '0',
    publishtype int(11) not null default '0',
    fingerprint varchar(250) binary null default null,
    publisherid int(11) not null default '0',
    volatiledata longtext null default null,
    primary key (pk)
);

drop table if exists servicedata;
create table servicedata (
    id int(11) not null default '0',
    name varchar(250) binary null default null,
    data longtext null default null,
    primary key (id)
);

drop table if exists tableprotectdata;
create table tableprotectdata (
    id varchar(250) binary not null default '',
    version int(11) not null default '0',
    hashversion int(11) not null default '0',
    protectionalg varchar(250) binary null default null,
    hash varchar(250) binary null default null,
    signature varchar(250) binary null default null,
    time bigint(20) not null default '0',
    dbkey varchar(250) binary null default null,
    dbtype varchar(250) binary null default null,
    keytype varchar(250) binary null default null,
    primary key (id)
);

drop table if exists userdata;
create table userdata (
    username varchar(250) binary not null default '',
    subjectdn varchar(250) binary null default null,
    caid int(11) not null default '0',
    subjectaltname varchar(250) binary null default null,
    subjectemail varchar(250) binary null default null,
    status int(11) not null default '0',
    type int(11) not null default '0',
    clearpassword varchar(250) binary null default null,
    passwordhash varchar(250) binary null default null,
    timecreated bigint(20) not null default '0',
    timemodified bigint(20) not null default '0',
    endentityprofileid int(11) not null default '0',
    certificateprofileid int(11) not null default '0',
    tokentype int(11) not null default '0',
    hardtokenissuerid int(11) not null default '0',
    extendedinformationdata longtext null default null,
    keystorepassword varchar(250) binary null default null,
    cardnumber varchar(19) binary null default null,
    primary key (username)
);

drop table if exists userdatasourcedata;
create table userdatasourcedata (
    id int(11) not null default '0',
    name varchar(250) binary null default null,
    updatecounter int(11) not null default '0',
    data longtext null default null,
    primary key (id)
);

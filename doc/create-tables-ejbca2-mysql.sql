
NOTE: This file is outdated and needs updating! Do not use!

use test;

drop table if exists accessrules;

create table accessrules (
	pk integer(10) primary key,
	accessrule blob,
	resource varchar(150),
	admingroupname varchar(150)
);

drop table if exists adminentity;

create table adminentity (
	matchwith integer(10),
	matchvalue varchar(150),
	pk integer(10) primary key,
	matchtype integer(10),
	admingroupname varchar(150)
);

drop table if exists admingroup;

create table admingroup (
	admingroupname varchar(150)
);

drop table if exists adminprefs;

create table adminprefs (
	data blob,
	id varchar(150) primary key
);

drop table if exists availableaccessrules;

create table availableaccessrules (
	name varchar(150)
);

drop table if exists certificatedata;

create table certificatedata (
	expiredate decimal(38),
	revocationdate decimal(38),
	subjectdn varchar(150),
	issuerdn varchar(150),
	cafingerprint varchar(150),
	base64cert text,
	fingerprint varchar(150),
	status integer(10),
	username varchar(150),
	serialnumber varchar(150),
	type integer(10),
	revocationreason integer(10)
);

drop table if exists certificateprofiledata;

create table certificateprofiledata (
	data blob,
	certificateprofilename varchar(150),
	id integer(10) primary key
);

drop table if exists crldata;

create table crldata (
	fingerprint varchar(10) primary key,
	nextupdate decimal(38),
	cafingerprint varchar(150),
	issuerdn varchar(150),
	thisupdate varchar(150),
	crlnumber integer(10),
	base64crl longtext
);

drop table if exists endentityprofile;

create table endentityprofile (
	profilename varchar(150),
	data blob,
	id integer(10) primary key
);

drop table if exists globalconfig;

create table globalconfig (
	configurationid varchar(150) primary key,
	data blob
);

drop table if exists logconfigurationdata;

create table logconfigurationdata (
	logconfiguration blob,
	logentryrownumber integer(10),
	id integer(10) primary key
);

drop table if exists logentrydata;

create table logentrydata (
	event integer(10),
	id integer(10) primary key,
	module integer(10),
	time decimal(38),
	certificatesnr varchar(150),
	username varchar(150),
	comment varchar(150),
	admindata varchar(150),
	admintype integer(10)
);

drop table if exists userdata;

create table userdata (
	keystorepassword varchar(150),
	subjectdn varchar(150),
	subjectaltname varchar(150),
	timemodified decimal(38),
	status integer(10),
	username varchar(150) primary key,
	certificateprofileid integer(10),
	timecreated decimal(38),
	type integer(10),
	hardtokenissuerid integer(10),
	passwordhash varchar(150),
	endentityprofileid integer(10),
	tokentype integer(10),
	clearpassword varchar(150),
	subjectemail varchar(150)
)

	










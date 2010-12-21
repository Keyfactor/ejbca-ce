# Version: $Id$


revoke ALL PRIVILEGES, GRANT OPTION from '${database.username}'@'%';
DROP USER '${database.username}'@'%';

grant LOCK TABLES on ${url.path}.* to '${database.username}'@'%' identified by '${database.password}';

grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.AccessRulesData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.AdminEntityData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.AdminGroupData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.AdminPreferencesData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.ApprovalData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.AuthorizationTreeUpdateData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.CAData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.CRLData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.CertReqHistoryData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.CertificateData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.CertificateProfileData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.EndEntityProfileData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.GlobalConfigurationData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.HardTokenCertificateMap to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.HardTokenData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.HardTokenIssuerData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.HardTokenProfileData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.HardTokenPropertyData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.KeyRecoveryData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.LogConfigurationData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.ProtectedLogExportData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.PublisherData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.PublisherQueueData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.ServiceData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.UserData to '${database.username}'@'%';
grant SELECT,INSERT,UPDATE,DELETE,INDEX on ${url.path}.UserDataSourceData to '${database.username}'@'%';

grant SELECT,INSERT on ${url.path}.LogEntryData to '${database.username}'@'%';

flush privileges;
show grants for '${database.username}'@'%';
exit

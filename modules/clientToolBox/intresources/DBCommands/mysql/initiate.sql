# Version: $Id$


drop database if exists ${url.path};
create database ${url.path};

revoke ALL PRIVILEGES, GRANT OPTION from '${database.username}'@'%';
DROP USER '${database.username}'@'%';

grant ALL on ${url.path}.* to '${database.username}'@'%' identified by '${database.password}';

flush privileges;
show grants for '${database.username}'@'%';
exit

#!/bin/bash -x

# A small script that can be used to change database engine in MySQL/MariaDB.
# Modify to fit your needs...

MYSQLCMD='mysql -u ejbca --password=ejbca'

for db in $*; do
        for table in `echo show tables | $MYSQLCMD $db | grep -v Tables_in_`; do
                TABLE_TYPE=`echo show create table $table | $MYSQLCMD $db | sed -e's/.*ENGINE=\([[:alnum:]\]\+\)[[:space:]].*/\1/'|grep -v 'Create Table'`
                if [ $TABLE_TYPE = "MyISAM" ] ; then
                        #mysqldump $db $table > $db.$table.sql
                        echo "ALTER TABLE $table ENGINE = InnoDB" | $MYSQLCMD $db
                fi
        done
done

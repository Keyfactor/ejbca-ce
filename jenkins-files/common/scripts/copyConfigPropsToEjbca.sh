#!/bin/sh

# !!! WARNING !!! Your may loose your configuration under EJBCA/conf folder using this script.
#
# This utility script uses the configuration of application server and database and copies it EJBCA/conf folder.
# copyConfigPropsToEjbca.sh BUILD_FOLDER_CONF EJBCA_CONF DOCKER_NAME_APP JDK_VERSION DB_FAMILY DB_VERSION SERVER_FAMILY SERVER_VERSION
#                           [1]                [2]       [3]            [4]         [5]       [6]        [7]           [8]
#echo
#echo "copyConfigPropsToEjbca.sh [$1] [$2] [$3] [$4] [$5] [$6] [$7] [$8]"
#echo

########################################################################################################################
# Copy resources
########################################################################################################################
cp $1/* $2/
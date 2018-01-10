#!/bin/bash
# /*************************************************************************
#  *                                                                       *
#  *  CESeCore: CE Security Core                                           *
#  *                                                                       *
#  *  This software is free software; you can redistribute it and/or       *
#  *  modify it under the terms of the GNU Lesser General Public           *
#  *  License as published by the Free Software Foundation; either         *
#  *  version 2.1 of the License, or any later version.                    *
#  *                                                                       *
#  *  See terms of license at gnu.org.                                     *
#  *                                                                       *
#  *************************************************************************/
#
# Test file for an external script logging to ERROUT and exit code 1. Parameter at position 1 is the full path of the DER certificate file.
# Parameter 3 must be integer and is returned as exit code.

echo "External script called with full path of certificate file as parameter 1"
echo "$0"
echo "$1"
(>&2 echo "Sample error.")
exit 1

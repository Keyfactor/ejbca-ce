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
# Test file for an external script logging to ERROUT and returning parameter 2 as exit code. Parameter at position 1 is the PEM certificate..
# Parameter 3 must be integer and is returned as exit code.

echo "External process with PEM certificate written to STDIN."
read cert
echo -e "$cert"
echo "$0"
echo "$1"
echo "$2"
# echo -e "$cert" | openssl x509 -text -noout
(>&2 echo "Sample error.")
exit $2

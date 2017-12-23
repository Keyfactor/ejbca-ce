@ECHO OFF
REM /*************************************************************************
REM  *                                                                       *
REM  *  CESeCore: CE Security Core                                           *
REM  *                                                                       *
REM  *  This software is free software; you can redistribute it and/or       *
REM  *  modify it under the terms of the GNU Lesser General Public           *
REM  *  License as published by the Free Software Foundation; either         *
REM  *  version 2.1 of the License, or any later version.                    *
REM  *                                                                       *
REM  *  See terms of license at gnu.org.                                     *
REM  *                                                                       *
REM  *************************************************************************/
REM 
REM Test file for an external script logging to ERROUT and returning exit code 1. Parameter at position 1 is the full path of the certificate file.

ECHO "External script called with full path of certificate file as parameter 1"
ECHO "Parameter 0: %0"
ECHO "Parameter 1: %1"
ECHO "Sample Error." 1>&2
EXIT /B 0
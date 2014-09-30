/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cli.infrastructure.command;

/**
 * Return value for CLI commands. Mostly to allow commands to fail well without having to toss an exception to the command line.
 * Unexpected failures should be handled by RunTimeException
 * 
 * @version $Id$
 *
 */
public enum CommandResult {
    SUCCESS(0), FUNCTIONAL_FAILURE(1), AUTHORIZATION_FAILURE(2), CLI_FAILURE(3);
    
    private final int returnCode;
    
    private CommandResult(int returnCode) {
        this.returnCode = returnCode;
    }
    
    public int getReturnCode() {
        return returnCode;
    }
}

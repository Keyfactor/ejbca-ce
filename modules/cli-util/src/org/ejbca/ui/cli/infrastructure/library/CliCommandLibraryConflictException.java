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
package org.ejbca.ui.cli.infrastructure.library;

/**
 * Exception thrown when trying to construct a CLI command library and a conflict occurs,
 * i.e the commands 
 * $ ra <params> 
 * $ ra adduser <params> 
 * both exist in the same command set. 
 * 
 * @version $Id$
 *
 */
public class CliCommandLibraryConflictException extends RuntimeException {

    private static final long serialVersionUID = 3697467436872840222L;
    
    public CliCommandLibraryConflictException() {
        super();
    }

    public CliCommandLibraryConflictException(String message, Throwable cause) {
        super(message, cause);
    }

    public CliCommandLibraryConflictException(String message) {
        super(message);
    }

    public CliCommandLibraryConflictException(Throwable cause) {
        super(cause);
    }

    

}

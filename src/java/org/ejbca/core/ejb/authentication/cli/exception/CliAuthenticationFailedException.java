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
package org.ejbca.core.ejb.authentication.cli.exception;

import javax.ejb.ApplicationException;

/**
 * This exception is thrown if authentication fails during the authorization phase of a CliAuthenticationToken
 * 
 * @version $Id$
 *
 */
@ApplicationException(rollback=true)  
public class CliAuthenticationFailedException extends Exception {

    private static final long serialVersionUID = 1092700837332116526L;

    public CliAuthenticationFailedException() {
        super();
    }

    public CliAuthenticationFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public CliAuthenticationFailedException(String message) {
        super(message);
    }

    public CliAuthenticationFailedException(Throwable cause) {
        super(cause);
    }

}

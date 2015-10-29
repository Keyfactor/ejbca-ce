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

/**
 * An exception thrown when a CliAuthenticationToken is used without having its password field set.
 * 
 * @version $Id$
 * 
 */
public class UninitializedCliAuthenticationTokenException extends RuntimeException {

    private static final long serialVersionUID = -3404632335972154544L;

    public UninitializedCliAuthenticationTokenException() {
        super();
    }

    public UninitializedCliAuthenticationTokenException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public UninitializedCliAuthenticationTokenException(String arg0) {
        super(arg0);
    }

    public UninitializedCliAuthenticationTokenException(Throwable arg0) {
        super(arg0);
    }

}

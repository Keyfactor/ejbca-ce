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
 
 
package org.ejbca.core.ejb;

import jakarta.xml.ws.WebFault;

/**
 * Exception related to resource localization.
 *
 * If such an exception is thrown it means anyway that the resource
 * lookup dramatically failed, which means that either it is a user
 * error or simply the server is totally down, so there is no point
 * in throwing a checked exception that the user won't really be
 * able to handle.
 * 
 * @version $Id$
 */
@WebFault
public class ServiceLocatorException extends Exception {

    private static final long serialVersionUID = -4079132608707751216L;

    public ServiceLocatorException() {
        super();
    }

    public ServiceLocatorException(String message) {
        super(message);
    }

    public ServiceLocatorException(Throwable cause) {
        super(cause);
    }

    public ServiceLocatorException(String message, Throwable cause) {
        super(message, cause);
    }
}

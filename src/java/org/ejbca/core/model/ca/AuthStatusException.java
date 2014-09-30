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
 
package org.ejbca.core.model.ca;

import org.ejbca.core.EjbcaException;



/**
 * Authentication error due to wrong status of user object. To authenticate a user the user must
 * have status new, failed or inprocess.
 *
 * @version $Id$
 */
public class AuthStatusException extends EjbcaException {
    private static final long serialVersionUID = -1399828365257002586L;

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public AuthStatusException(String message) {
        super(message);
    }
}

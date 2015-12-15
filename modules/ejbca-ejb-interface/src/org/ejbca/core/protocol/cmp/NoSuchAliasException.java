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
 
package org.ejbca.core.protocol.cmp;

import org.ejbca.core.EjbcaException;



/**
 * Error due to wrong CMP alias
 *
 * @version $Id$
 */
public class NoSuchAliasException extends EjbcaException {

    private static final long serialVersionUID = -5521689458199668528L;
    /**
     * Constructor used to create exception with an error message. Calls the same constructor in
     * base class <code>Exception</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public NoSuchAliasException(String message) {
        super(message);
    }
}

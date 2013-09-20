/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.user.matchvalues;

/**
 * Thrown if an error occurs during reverse lookup
 * 
 * @version $Id$
 *
 */
public class ReverseMatchValueLookupException extends RuntimeException{

    private static final long serialVersionUID = -7869788516422286307L;

    public ReverseMatchValueLookupException() {
        super();
    }

    public ReverseMatchValueLookupException(String message, Throwable cause) {
        super(message, cause);
    }

    public ReverseMatchValueLookupException(String message) {
        super(message);
    }

    public ReverseMatchValueLookupException(Throwable cause) {
        super(cause);
    }

}

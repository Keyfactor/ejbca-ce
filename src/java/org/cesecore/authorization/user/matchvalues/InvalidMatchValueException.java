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
 * This runtime exception is thrown to signify that an attempt of an enum to extend the AccessMatchValue
 * interface failed and could not be recovered.
 * 
 * @version $Id$
 *
 */
public class InvalidMatchValueException extends RuntimeException {

    private static final long serialVersionUID = -7145630440532075247L;

    public InvalidMatchValueException() {
        super();
    }

    public InvalidMatchValueException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidMatchValueException(String message) {
        super(message);
    }

    public InvalidMatchValueException(Throwable cause) {
        super(cause);
    }

}

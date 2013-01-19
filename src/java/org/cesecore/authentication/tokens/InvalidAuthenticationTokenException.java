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
package org.cesecore.authentication.tokens;

/**
 * Thrown when an invalid AuthenticationToken is encountered.
 * 
 * @version $Id$
 *
 */
public class InvalidAuthenticationTokenException extends RuntimeException {

    private static final long serialVersionUID = -8887523864100620342L;

    public InvalidAuthenticationTokenException() {

    }

    public InvalidAuthenticationTokenException(String message) {
        super(message);
    }

    public InvalidAuthenticationTokenException(Throwable e) {
        super(e);
    }

    public InvalidAuthenticationTokenException(String message, Throwable e) {
        super(message, e);
    }

}

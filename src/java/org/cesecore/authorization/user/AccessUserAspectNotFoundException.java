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
package org.cesecore.authorization.user;

/**
 * Thrown when an AccessUserAspect is not found.
 * 
 * @version $Id$
 *
 */
public class AccessUserAspectNotFoundException extends RuntimeException {

    private static final long serialVersionUID = -3503860340121024920L;

    public AccessUserAspectNotFoundException() {
        super();
    }

    public AccessUserAspectNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessUserAspectNotFoundException(String message) {
        super(message);
    }

    public AccessUserAspectNotFoundException(Throwable cause) {
        super(cause);
    } 

    

}

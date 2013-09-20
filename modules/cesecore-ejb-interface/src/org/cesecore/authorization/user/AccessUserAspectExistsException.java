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
 * @version $Id$
 *
 */
public class AccessUserAspectExistsException extends Exception {

    private static final long serialVersionUID = -3503860340121024920L;

    public AccessUserAspectExistsException() {
        super();
    }

    public AccessUserAspectExistsException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessUserAspectExistsException(String message) {
        super(message);
    }

    public AccessUserAspectExistsException(Throwable cause) {
        super(cause);
    } 

    

}

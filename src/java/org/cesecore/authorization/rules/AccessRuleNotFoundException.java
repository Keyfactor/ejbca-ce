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
package org.cesecore.authorization.rules;

/**
 * Thrown when accessing an access rule that doesn't exist.
 * 
 * Based on cesecore version:
 *      AccessRuleNotFoundException.java 249 2011-02-11 17:40:39Z filiper
 * 
 * @version $Id$
 *
 */
public class AccessRuleNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1340738456351111597L;

    public AccessRuleNotFoundException() {
        super();
    }

    public AccessRuleNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessRuleNotFoundException(String message) {
        super(message);
    }

    public AccessRuleNotFoundException(Throwable cause) {
        super(cause);
    }


}

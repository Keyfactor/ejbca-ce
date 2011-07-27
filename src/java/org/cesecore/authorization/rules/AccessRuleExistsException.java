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
 * Thrown when creating an access rule that already exists.
 * 
 * Based on cesecore version:
 *      AccessRuleExistsException.java 160 2011-01-26 15:03:43Z tomas
 * 
 * @version $Id$
 *
 */
public class AccessRuleExistsException extends Exception{

    private static final long serialVersionUID = 1340738456351111597L;

    public AccessRuleExistsException() {
        super();
    }

    public AccessRuleExistsException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessRuleExistsException(String message) {
        super(message);
    }

    public AccessRuleExistsException(Throwable cause) {
        super(cause);
    }


}

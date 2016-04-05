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
package org.cesecore.authorization.access;

import java.io.Serializable;

/**
 * You can have a method that has a parameter of this type with the &#64;Observes attribute to be
 * notified when the access rules or roles have been changed. Please make the method
 * &#64;Asynchronous so it doesn't block the caller (currently
 * {@link org.cesecore.authorization.cache.AccessTreeUpdateSessionBean#signalForAccessTreeUpdate()})
 * 
 * @version $Id$
 */
public final class AuthorizationCacheReload implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final int accessTreeUpdateNumber;
    
    public AuthorizationCacheReload(final int accessTreeUpdateNumber) {
        this.accessTreeUpdateNumber = accessTreeUpdateNumber;
    }
    
    public int getAccessTreeUpdateNumber() {
        return accessTreeUpdateNumber;
    }

}

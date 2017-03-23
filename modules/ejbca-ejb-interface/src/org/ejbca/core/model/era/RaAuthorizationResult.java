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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.HashMap;

/**
 * Result of an authorization request.
 * 
 * @version $Id$
 * @since RaMasterApi version 1
 */
public class RaAuthorizationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private final HashMap<String, Boolean> accessRules;
    private final int updateNumber;
    
    public RaAuthorizationResult(final HashMap<String, Boolean> accessRules, final int updateNumber) {
        this.accessRules = accessRules;
        this.updateNumber = updateNumber;
    }
    
    public HashMap<String, Boolean> getAccessRules() { return accessRules; }
    public int getUpdateNumber() { return updateNumber; }
}

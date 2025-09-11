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
 * Result of an authorization request from RA.
 * 
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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((accessRules == null) ? 0 : accessRules.hashCode());
        result = prime * result + updateNumber;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RaAuthorizationResult other = (RaAuthorizationResult) obj;
        if (accessRules == null) {
            if (other.accessRules != null)
                return false;
        } else if (!accessRules.equals(other.accessRules))
            return false;
        if (updateNumber != other.updateNumber)
            return false;
        return true;
    }
}

/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.roles;

import java.io.Serializable;
import java.util.List;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.AccessUserAspectData;

/**
 * Container POJO used due to the fact RoleData in certain contexts doesn't survive encoding to JSF
 * 
 * @version $Id$
 *
 */
public class RoleInformation implements Serializable {
    private static final long serialVersionUID = 1L;
    private final int identifier;
    private final String name;
    private final List<AccessUserAspectData> accessUserAspects;

    public RoleInformation(final int identifier, final String name, final List<AccessUserAspectData> accessUserAspects) {
        this.identifier = identifier;
        this.name = name;
        this.accessUserAspects = accessUserAspects;
    }

    public String getName() {
        return name;
    }

    public int getIdentifier() {
        return identifier;
    }

    @Override
    public String toString() {
        return name;
    }

    @Override
    public int hashCode() {
        final int prime = 37;
        int result = 1;
        result = prime * result + identifier;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
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
        RoleInformation other = (RoleInformation) obj;
        if (identifier != other.identifier)
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        return true;
    }

    public List<AccessUserAspectData> getAccessUserAspects() {
        return accessUserAspects;
    }

}

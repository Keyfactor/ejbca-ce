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

import java.util.Collection;

import javax.ejb.Remote;

import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.roles.RoleData;

/**
 * Local interface for AccessUserAspectSession
 * 
 * Based on cesecore version:
 *      AccessUserAspectManagerTestSessionRemote.java 937 2011-07-14 15:57:25Z mikek
 * 
 * @version $Id$
 *
 */
@Remote
public interface AccessUserAspectManagerTestSessionRemote {

    void persistAccessUserAspect(AccessUserAspect accessUserAspectData);
    
    public AccessUserAspectData create(final RoleData role, final int caId,
            final X500PrincipalAccessMatchValue matchWith, final AccessMatchType matchType, final String matchValue) throws AccessUserAspectExistsException;

    AccessUserAspect find(int primaryKey);

    void remove(AccessUserAspectData userAspect);

    void remove(Collection<AccessUserAspectData> userAspects);

}

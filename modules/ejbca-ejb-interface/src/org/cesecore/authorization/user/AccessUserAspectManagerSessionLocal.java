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

import javax.ejb.Local;

import org.cesecore.roles.RoleData;

/**
 * Local interface for AccessUserAspectSession
 * 
 * Based on cesecore version:
 *      AccessUserAspectManagerSessionLocal.java 937 2011-07-14 15:57:25Z mikek
 * 
 * @version $Id$
 *
 */
@Local
public interface AccessUserAspectManagerSessionLocal {

    /**
     * Persists an unpersisted AccessUserAspectData object.
     * 
     * @param accessUserAspectData the AccessUserAspectData to persist.
     */
    void persistAccessUserAspect(AccessUserAspect accessUserAspectData);
    
    /**
     * Creates a new {@link AccessUserAspectData}
     * 
     * @param role
     *            The role which this access user aspect is to belong. Used to generate primary key.
     * @param caId
     *            ID of the CA associated with this access user aspect.
     * @param matchWith
     *            What kind of value to match with.
     * @param matchType
     *            How to match.
     * @param matchValue
     *            Value to match with.
     * @return The persisted access user aspect.
     * @throws AccessUserAspectExistsException
     *             if a user with this primary key already is persisted.
     */
    public AccessUserAspectData create(final RoleData role, final int caId,
            final X500PrincipalAccessMatchValue matchWith, final AccessMatchType matchType, final String matchValue) throws AccessUserAspectExistsException;

    /**
     * Finds an AccessUserAspectData by its primary key. A primary key can be generated statically from AccessUserAspectData.
     * 
     * @param primaryKey
     *            Primary key of the sought instance.
     * @return An unattached instance of AccessUserAspectData, null otherwise.
     */
    AccessUserAspectData find(int primaryKey);

    /**
     * Removes an AccessUserAspectData from the database.
     * 
     * @param userAspect
     *            The AccessUserAspectData to remove.
     */
    void remove(AccessUserAspectData userAspect);

    /**
     * Removes a <code>Collection</code> of AccessUserAspectData objects from the database.
     * 
     * @param userAspects
     *            A <code>Collection</code> of AccessUserAspectData objects
     */
    void remove(Collection<AccessUserAspectData> userAspects);
    


}

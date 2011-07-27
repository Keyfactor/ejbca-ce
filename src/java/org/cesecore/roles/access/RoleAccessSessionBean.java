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
package org.cesecore.roles.access;

import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.util.QueryResultWrapper;

/**
 * @version $Id: RoleAccessSessionBean.java 854 2011-05-24 12:57:17Z johane $
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleAccessSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class RoleAccessSessionBean implements RoleAccessSessionLocal, RoleAccessSessionRemote {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    /**
     * Returns all roles.
     * 
     * @see org.cesecore.roles.management.RoleManagementSession#getAllRoles()
     */
    @SuppressWarnings("unchecked")
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<RoleData> getAllRoles() {
        final Query query = entityManager.createQuery("SELECT a FROM RoleData a");
        return (query.getResultList() != null ? query.getResultList() : new ArrayList<RoleData>());
    }

    /**
     * Finds a specific role by name.
     * 
     * @see org.cesecore.roles.management.RoleManagementSession#getRole(java.lang.String)
     * 
     * @param token
     *            An authentication token.
     * @param roleName
     *            Name of the sought role.
     * @return The sought roll, null otherwise.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public RoleData findRole(final String roleName) {
        final Query query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.roleName=:roleName");
        query.setParameter("roleName", roleName);
        return (RoleData) QueryResultWrapper.getSingleResult(query);
    }

    /**
     * Finds a RoleData object by its primary key.
     * 
     * @param primaryKey
     *            The primary key.
     * @return the found entity instance or null if the entity does not exist.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public RoleData findRole(final Integer primaryKey) {
        final Query query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.primaryKey=:primaryKey");
        query.setParameter("primaryKey", primaryKey);

        return (RoleData) QueryResultWrapper.getSingleResult(query);
    }
}

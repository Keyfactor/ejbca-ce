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
import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.util.QueryResultWrapper;

/**
 * @version $Id$
 *
 */
@Deprecated
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class RoleAccessSessionBean implements RoleAccessSessionLocal {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @SuppressWarnings("unchecked")
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AdminGroupData> getAllRoles() {
        final Query query = entityManager.createQuery("SELECT a FROM AdminGroupData a");
        return (query.getResultList() != null ? query.getResultList() : new ArrayList<AdminGroupData>());
    }


    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroupData findRole(final String roleName) {
        final TypedQuery<AdminGroupData> query = entityManager.createQuery("SELECT a FROM AdminGroupData a WHERE a.roleName=:roleName", AdminGroupData.class);
        query.setParameter("roleName", roleName);
        return QueryResultWrapper.getSingleResult(query);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroupData findRole(final Integer primaryKey) {
        return entityManager.find(AdminGroupData.class, primaryKey);
    }
}

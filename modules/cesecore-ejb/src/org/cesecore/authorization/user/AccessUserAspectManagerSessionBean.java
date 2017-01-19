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

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.ValueExtractor;

/**
 * Implementation of AccessUserAspectManagerSession
 * 
 * @version $Id$
 * 
 * @deprecated Use RoleMemberManagementSession instead
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessUserAspectManagerSessionLocal")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AccessUserAspectManagerSessionBean implements AccessUserAspectManagerSessionLocal {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void persistAccessUserAspect(AccessUserAspectData accessUserAspectData) throws AccessUserAspectExistsException {
        if (find(accessUserAspectData.getPrimaryKey()) == null && find(accessUserAspectData.getLegacyPrimaryKey()) == null) {
            entityManager.persist(accessUserAspectData);
        } else {
            throw new AccessUserAspectExistsException("Access user aspect already exists in database.");
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public AccessUserAspectData create(final AdminGroupData role, final int caId, final AccessMatchValue matchWith, final AccessMatchType matchType,
            final String matchValue) throws AccessUserAspectExistsException {
        AccessUserAspectData result = new AccessUserAspectData(role.getRoleName(), caId, matchWith, matchType, matchValue);
        persistAccessUserAspect(result);
        return result;
    }

    @Override
    public AccessUserAspectData find(int primaryKey) {
        final Query query = entityManager.createQuery("SELECT a FROM AccessUserAspectData a WHERE a.primaryKey=:primaryKey");
        query.setParameter("primaryKey", primaryKey);
        return (AccessUserAspectData) QueryResultWrapper.getSingleResult(query);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void remove(AccessUserAspectData userAspect) {
        userAspect = entityManager.merge(userAspect);
        entityManager.remove(userAspect);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void remove(Collection<AccessUserAspectData> userAspects) {
        for (AccessUserAspectData userAspect : userAspects) {
            remove(userAspect);
        }

    }
    
    @Override
    public boolean existsCAInAccessUserAspects(int caId) {
        final Query query = entityManager.createQuery("SELECT COUNT(a) FROM AccessUserAspectData a WHERE a.caId=:caId");
        query.setParameter("caId", caId);
        long count = ValueExtractor.extractLongValue(query.getSingleResult());

        return count > 0;
    }
   
}

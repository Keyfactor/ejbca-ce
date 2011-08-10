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

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.util.ValueExtractor;

/**
 * Implementation of AccessUserAspectManagerSession
 * 
 * Based on cesecore version:
 *      AccessUserAspectManagerSessionBean.java 937 2011-07-14 15:57:25Z mikek
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessUserAspectManagerSessionLocal")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AccessUserAspectManagerSessionBean implements AccessUserAspectManagerSessionLocal {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void persistAccessUserAspect(AccessUserAspect accessUserAspectData) {
        entityManager.persist(accessUserAspectData);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public AccessUserAspectData create(final RoleData role, final int caId,
            final AccessMatchValue matchWith, final AccessMatchType matchType, final String matchValue) throws AccessUserAspectExistsException {
        AccessUserAspectData result = null;

        if (find(AccessUserAspectData.generatePrimaryKey(role.getRoleName(), caId, matchWith, matchType, matchValue)) == null) {
            result = new AccessUserAspectData(role.getRoleName(), caId, matchWith, matchType, matchValue);
            entityManager.persist(result);
        } else {
            throw new AccessUserAspectExistsException("Access user aspect already exists in database.");
        }

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

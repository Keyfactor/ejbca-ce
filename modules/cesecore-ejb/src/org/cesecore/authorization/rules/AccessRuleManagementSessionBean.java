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
package org.cesecore.authorization.rules;

import java.util.Collection;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.ValueExtractor;

/**
 * Implementation of AccessRuleManagementSession class
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessRuleManagementSessionLocal")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AccessRuleManagementSessionBean implements AccessRuleManagementSessionLocal {

    private static final Logger log = Logger.getLogger(AccessRuleManagementSessionBean.class);
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public AccessRuleData find(int primaryKey) {
        final Query query = entityManager.createQuery("SELECT a FROM AccessRuleData a WHERE a.primaryKey=:primaryKey");
        query.setParameter("primaryKey", primaryKey);
        return (AccessRuleData) QueryResultWrapper.getSingleResult(query);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void remove(AccessRuleData accessRule) {
        if (!entityManager.contains(accessRule)) {
            accessRule = find(accessRule.getPrimaryKey());
        }
        entityManager.remove(accessRule);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void remove(Collection<AccessRuleData> accessRules) {
        for (AccessRuleData accessRule : accessRules) {
            remove(accessRule);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.MANDATORY)
    public AccessRuleData setState(final AccessRuleData rule, final AccessRuleState state, boolean isRecursive) {
        AccessRuleData result = find(rule.getPrimaryKey());
        result.setInternalState(state);
        result.setRecursive(isRecursive);
        return result;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public AccessRuleData createRule(final String accessRuleName, final String roleName, final AccessRuleState state, boolean isRecursive)
            throws AccessRuleExistsException {
        AccessRuleData result = null;
        int primaryKey = AccessRuleData.generatePrimaryKey(roleName, accessRuleName);

        if (find(primaryKey) == null) {
            result = new AccessRuleData(primaryKey, accessRuleName, state, isRecursive);
            entityManager.persist(result);
        } else {
            throw new AccessRuleExistsException("Access rule of name '" + accessRuleName + "' belonging to role '" + roleName + "' already exists.");
        }

        return result;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void persistRule(AccessRuleData rule) {
        entityManager.persist(rule);
    }
    
    @Override
    public boolean existsCaInAccessRules(int caid) {
        if (log.isTraceEnabled()) {
            log.trace(">existsCAInAccessRules(" + caid + ")");
        }
        String whereClause = "accessRule = '" + StandardRules.CAACCESSBASE.resource() + "/" + caid + "' OR accessRule LIKE '"
                + StandardRules.CAACCESSBASE.resource() + "/" + caid + "/%'";
        Query query = entityManager.createNativeQuery("SELECT COUNT(*) FROM AccessRulesData a WHERE " + whereClause);
        long count = ValueExtractor.extractLongValue(query.getSingleResult());
        if (log.isTraceEnabled()) {
            log.trace("<existsCAInAccessRules(" + caid + "): " + count);
        }
        return count > 0;
    }

}

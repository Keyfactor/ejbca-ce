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
package org.ejbca.core.ejb.audit;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;

/**
 * Proxy to make EjbcaAuditorSessionLocal testable over RMI.
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EjbcaAuditorTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EjbcaAuditorTestSessionBean implements EjbcaAuditorTestSessionRemote {

    private static final Logger LOG = Logger.getLogger(EjbcaAuditorTestSessionBean.class);
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    @EJB
    private EjbcaAuditorSessionLocal ejbcaAuditorSession;
    
    @Override
    public List<? extends AuditLogEntry> selectAuditLog(AuthenticationToken token, String device, int firstResult, int maxResults, String whereClause,
            String orderClause, List<Object> parameters) throws AuthorizationDeniedException {
        return ejbcaAuditorSession.selectAuditLog(token, device, firstResult, maxResults, whereClause, orderClause, parameters);
    }
    
    @Override
    public List<? extends AuditLogEntry> selectAuditLogNoAuth(final AuthenticationToken token, final String device, final int firstResult, final int maxResults,
            final String whereClause, final String orderClause, final List<Object> parameters) throws AuthorizationDeniedException {
        if (!IntegrityProtectedDevice.class.getSimpleName().equals(device)) {
            throw new UnsupportedOperationException("selectAuditLog can only be used with " + IntegrityProtectedDevice.class.getSimpleName());
        }
        // Start building the query
        final StringBuilder queryBuilder = new StringBuilder("SELECT a FROM ").append(AuditRecordData.class.getSimpleName()).append(" a");
        // Optionally add the WHERE clause
        if (whereClause!=null && whereClause.length()>0) {
            queryBuilder.append(" WHERE ").append(whereClause);
        }
        // Optionally add the ORDER clause
        if (orderClause!=null && orderClause.length()>0) {
            queryBuilder.append(" ORDER BY ").append(orderClause);
        }
        final String queryString = queryBuilder.toString();
        if (LOG.isDebugEnabled()) {
            LOG.debug("queryString: " + queryString);
        }
        final TypedQuery<AuditLogEntry> query = entityManager.createQuery(queryString, AuditLogEntry.class);
        query.setFirstResult(firstResult);
        if (maxResults>0) {
            query.setMaxResults(maxResults);
        }
        if (parameters!=null) {
            for (int i=0; i<parameters.size(); i++) {
                query.setParameter(i, parameters.get(i));
            }
        }

        return query.getResultList();
        
    }
}

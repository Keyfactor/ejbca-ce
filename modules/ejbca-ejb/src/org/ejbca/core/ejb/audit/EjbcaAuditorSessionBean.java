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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.config.CesecoreConfiguration;

/**
 * Workaround for the very complex CESeCore query criteria API.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EjbcaAuditorSessionBean implements EjbcaAuditorSessionLocal {

    private static final Logger LOG = Logger.getLogger(EjbcaAuditorSessionBean.class);
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private CaSessionLocal caSession;

    @SuppressWarnings("unchecked")
    @Override
    public List<? extends AuditLogEntry> selectAuditLog(final AuthenticationToken token, final String device, final int firstResult, final int maxResults,
            final String whereClause, final String orderClause, final List<Object> parameters) throws AuthorizationDeniedException {
        if (!IntegrityProtectedDevice.class.getSimpleName().equals(device)) {
            throw new UnsupportedOperationException("selectAuditLog can only be used with " + IntegrityProtectedDevice.class.getSimpleName());
        }
        // Require that the caller is authorized to AUDITLOGSELECT just like in org.cesecore.audit.audit.SecurityEventsAuditorSessionBean.selectAuditLogs(...)
        assertAuthorization(token, AuditLogRules.VIEW.resource());
        // Assert that parameter is alphanumeric or one of ". ?<>!="
        assertLegalSqlString(whereClause, true);
        // Assert that parameter is alphanumeric or one of ". "
        assertLegalSqlString(orderClause, false);
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
        final Query query = entityManager.createQuery(queryString);
        query.setFirstResult(firstResult);
        if (maxResults>0) {
            query.setMaxResults(maxResults);
        }
        if (parameters!=null) {
            for (int i=0; i<parameters.size(); i++) {
                query.setParameter(i, parameters.get(i));
            }
        }

        //Prune out result pertaining to unauthorized CAs
        Set<Integer> authorizedCaIds = new HashSet<>(caSession.getAuthorizedCaIds(token));
        List<AuditLogEntry> resultList = new ArrayList<>();
        for(AuditLogEntry auditLogEntry : (List<AuditLogEntry>) query.getResultList()) {
            if (auditLogEntry.getModuleTypeValue().equals(ModuleTypes.CA)) {
                if (!StringUtils.isEmpty(auditLogEntry.getCustomId())) {
                    if (!authorizedCaIds.contains(Integer.valueOf(auditLogEntry.getCustomId()))) {
                        continue;
                    }
                }
            }
            resultList.add(auditLogEntry);
        }
        return resultList;
        
    }

    /**
     * Make sure that the SQL query doesn't contain illegal characters.
     * A-Z, a-z, 0-9, ' ' and '.' are always allowed.
     * @param isWhere if true we also allow '?', '<', '>', '!' and '='
     * @throws IllegalArgumentException if an illegal character is found in the sql paramater
     */
    private void assertLegalSqlString(final String sql, final boolean isWhere) throws IllegalArgumentException {
        if (sql==null) {
            return; // no String is safe
        }
        for (int i=0; i<sql.length(); i++) {
            final char c = sql.charAt(i);
            if ((c>='0' && c<='9') || (c>='A' && c<='Z') || (c>='a' && c<='z') || c==' ' || c=='.') {
                continue; // ok
            }
            if (isWhere) {
                if (c=='?' || c=='<' || c=='>' || c=='!' || c=='=') {
                    continue; // ok
                }
            }
            // Char was not in the white-list.. warn and throw an error!
            LOG.warn("Possible SQL injection attempt: " + sql);
            throw new IllegalArgumentException(c + " is not a legal SQL query character.");
        }
    }

    /** Assert that we are authorized to the requested resource. */
    private void assertAuthorization(final AuthenticationToken token, final String accessRule) throws AuthorizationDeniedException {
        if (!accessControlSession.isAuthorized(token, accessRule)) {
            throw new AuthorizationDeniedException("not authorized to: "+ token.toString());                
        } 
    }

}

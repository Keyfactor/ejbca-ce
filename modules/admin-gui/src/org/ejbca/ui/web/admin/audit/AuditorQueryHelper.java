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
package org.ejbca.ui.web.admin.audit;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Helper class for building and executing audit log queries that are safe from SQL injection.
 * 
 * @version $Id$
 */
public abstract class AuditorQueryHelper {

    private static final Logger log = Logger.getLogger(AuditorQueryHelper.class);
    private static final String ERROR_MSG = "This should never happen unless you are intentionally trying to perform an SQL injection attack.";
    
    /**
     * Build and executing audit log queries that are safe from SQL injection.
     * 
     * @param token the requesting entity
     * @param validColumns a Set of legal column names
     * @param device the name of the audit log device
     * @param conditions the list of conditions to transform into a query
     * @param sortColumn ORDER BY column
     * @param sortOrder true=ASC, false=DESC order
     * @param firstResult first entry from the result set. Index starts with 0.
     * @param maxResults number of results to return
     * @return the query result
     * @throws AuthorizationDeniedException if the administrator is not authorized to perform the requested query
     */
    static List<? extends AuditLogEntry> getResults(final AuthenticationToken token, final Set<String> validColumns, final String device,
            final List<AuditSearchCondition> conditions, final String sortColumn, final boolean sortOrder, final int firstResult, final int maxResults)
            throws AuthorizationDeniedException {
        final List<Object> parameters = new ArrayList<Object>();
        final StringBuilder whereClause = new StringBuilder();
        for (int i=0; i<conditions.size(); i++) {
            final AuditSearchCondition condition = conditions.get(i);
            if (i>0) {
                switch (condition.getOperation()) {
                case AND:
                    whereClause.append(" AND "); break;
                case OR:
                    whereClause.append(" OR "); break;
                }
            }
            // Validate that the column we are adding to the SQL WHERE clause is exactly one of the legal column names
            if (!validColumns.contains(condition.getColumn())) {
                throw new RuntimeException(ERROR_MSG);
            }
            Object conditionValue = condition.getValue();
            if (AuditLogEntry.FIELD_TIMESTAMP.equals(condition.getColumn())) {
                try {
                    conditionValue = Long.valueOf(ValidityDate.parseAsIso8601(conditionValue.toString()).getTime());
                } catch (ParseException e) {
                    log.debug("Admin entered invalid date for audit log search: " + condition.getValue());
                    continue;
                }
            }
            switch (Condition.valueOf(condition.getCondition())) {
            case EQUALS:
                whereClause.append("a.").append(condition.getColumn()).append(" = ?").append(i); break;
            case NOT_EQUALS:
                whereClause.append("a.").append(condition.getColumn()).append(" != ?").append(i); break;
            case CONTAINS:
                whereClause.append("a.").append(condition.getColumn()).append(" LIKE ?").append(i);
                conditionValue = "%" + conditionValue + "%";
                break;
            case ENDS_WITH:
                whereClause.append("a.").append(condition.getColumn()).append(" LIKE ?").append(i);
                conditionValue = "%" + conditionValue;
                break;
            case STARTS_WITH:
                whereClause.append("a.").append(condition.getColumn()).append(" LIKE ?").append(i);
                conditionValue = conditionValue + "%";
                break;
            case GREATER_THAN:
                whereClause.append("a.").append(condition.getColumn()).append(" > ?").append(i); break;
            case LESS_THAN:
                whereClause.append("a.").append(condition.getColumn()).append(" < ?").append(i); break;
            default:
                throw new RuntimeException(ERROR_MSG);    
            }
            // The condition value will be added to the query using JPA's setParameter (safe from SQL injection)
            parameters.add(conditionValue);
        }
        // Validate that the column we are adding to the SQL ORDER clause is exactly one of the legal column names
        if (!validColumns.contains(sortColumn)) {
            throw new RuntimeException(ERROR_MSG);
        }
        final String orderClause = new StringBuilder("a.").append(sortColumn).append(sortOrder?" ASC":" DESC").toString();
        return new EjbLocalHelper().getEjbcaAuditorSession().selectAuditLog(token, device, firstResult, maxResults, whereClause.toString(), orderClause, parameters);
    }
}

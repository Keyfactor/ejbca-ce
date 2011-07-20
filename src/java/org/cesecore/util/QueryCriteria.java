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
package org.cesecore.util;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Query Criteria DSL.
 * 
 * There is no guarantee that this will contain a query that is nice to the database
 * when sent from a third party.
 * 
 * There is no support for prioritizing certain conditions using parenthesis.
 * 
 * Example usage:
 *   String conditions = QueryCriteria.where().eq("columnName", value).order("anotherColumn", QueryCriteria.ORDER_ASC).conditions(ExampleData.class);
 *   List<ExampleData> examples = entityManager.createQuery("SELECT a FROM ExampleData a" + conditions).getResultList();
 *
 * Based on CESeCore version:
 *      QueryCriteria.java 930 2011-07-05 14:03:08Z johane
 *
 * @version $Id$
 */
public class QueryCriteria implements Serializable {
	
	public static final boolean ORDER_ASC = true;
	public static final boolean ORDER_DESC = false;

    private static final long serialVersionUID = -730792160188560822L;
    
    private final Map<String, Object> parameters = new LinkedHashMap<String, Object>();
    private final StringBuilder query = new StringBuilder();
    private final Set<String> names = new HashSet<String>();
    private boolean hasCondition = false;
    
    private QueryCriteria() {
    }

    /** @return a new QueryCriteria */
    public static QueryCriteria where() {
        return new QueryCriteria();
    }

    /** @return the query with an appended "equal to" condition */
    public QueryCriteria eq(final String name, final Object value) {
    	hasCondition = true;
        final String parameter = genAndStoreParameter(name, value);
        query.append(" a.").append(name).append(" = :").append(parameter);
        return this;
    }

    /** @return the query with an appended "not equal to" condition */
    public QueryCriteria neq(final String name, final Object value) {
    	hasCondition = true;
        final String parameter = genAndStoreParameter(name, value);
        query.append(" a.").append(name).append(" != :").append(parameter);
        return this;
    }

    /** @return the query with an appended "greater than or equal to" condition */
    public QueryCriteria geq(final String name, final Object value) {
    	hasCondition = true;
        final String parameter = genAndStoreParameter(name, value);
        query.append(" a.").append(name).append(" >= :").append(parameter);
        return this;
    }

    /** @return the query with an appended "greater than" condition */
    public QueryCriteria grt(final String name, final Object value) {
    	hasCondition = true;
    	final String parameter = genAndStoreParameter(name, value);
        query.append(" a.").append(name).append(" > :").append(parameter);
        return this;
    }

    /** @return the query with an appended "less than or equal to" condition */
    public QueryCriteria leq(final String name, final Object value) {
    	hasCondition = true;
    	final String parameter = genAndStoreParameter(name, value);
        query.append(" a.").append(name).append(" <= :").append(parameter);
        return this;
    }

    /** @return the query with an appended "less than to" condition */
    public QueryCriteria lsr(final String name, final Object value) {
    	hasCondition = true;
        final String parameter = genAndStoreParameter(name, value);
        query.append(" a.").append(name).append(" < :").append(parameter);
        return this;
    }

    /** @return the query with an appended "between" condition */
    public QueryCriteria between(final String name, final Object after, final Object before) {
    	hasCondition = true;
        final String parameterAfter = genAndStoreParameter(name, after);
        final String parameterBefore = genAndStoreParameter(name, before);
        query.append(" a.").append(name).append(" BETWEEN :").append(parameterAfter).append(" AND :").append(parameterBefore);
        return this;
    }

    /** @return the query with an appended "like" condition */
    public QueryCriteria like(final String name, final Object value) {
    	hasCondition = true;
        final String parameter = genAndStoreParameter(name, value);
        query.append(" a.").append(name).append(" LIKE :").append(parameter);
        return this;
    }

    /** @return the query with an appended "is null" condition */
    public QueryCriteria isNull(final String name) {
    	hasCondition = true;
        query.append(" a.").append(name).append(" IS NULL");
        return this;
    }
    
    /** @return the query with an appended "is not null" condition */
    public QueryCriteria isNotNull(final String name) {
    	hasCondition = true;
        query.append(" a.").append(name).append(" IS NOT NULL");
        return this;
    }

    /** @return the query with an appended "and" condition */
    public QueryCriteria and() {
        query.append(" AND");
        return this;
    }

    /** @return the query with an appended "or" condition */
    public QueryCriteria or() {
        query.append(" OR");
        return this;
    }

    /** @return the query with an appended "ordering" condition. Use QueryCriteria.ORDER_ASC or QueryCriteria.ORDER_DESC. */
    public QueryCriteria order(final String name, final boolean ascending) {
        query.append(" ORDER BY a.").append(name);
        if (ascending) {
        	query.append(" ASC");
        } else {
        	query.append(" DESC");
        }
        return this;
    }

    /** @return the query as a String after validation of the fields of the supplied class. */
    public String conditions(final Class<?> entity) {
        for (final Field f : entity.getDeclaredFields()) {
        	names.remove(f.getName());
        }
    	if (!names.isEmpty()) {
    		final StringBuilder sb = new StringBuilder();
    		for (final String name : names) {
    			if (sb.length()!=0) {
    				sb.append(",");
    			}
    			sb.append(name);
    		}
    		throw new QueryParameterException("parameters do not match any entity fields: " + sb.toString());
    	}
    	if (hasCondition) {
    		hasCondition = false;	// Reset so we can call this method multiple times
    		query.insert(0, " WHERE");
    	}
        return query.toString();
    }

    /** @return all stored parameter names. */
    public Set<String> getParameterKeys() {
        return parameters.keySet();
    }

    /** @return the value of a stored parameter */
    public Object getParameterValue(final String key) {
    	return parameters.get(key);
    }

    private String genAndStoreParameter(final String name, final Object value) {
    	names.add(name);
    	int i = 0;
    	while (true) {
    		final String parameter = name + Integer.valueOf(i++).toString();
            if (!parameters.containsKey(parameter)) {
            	parameters.put(parameter, value);
            	return parameter;
            }
    	}
    }
}

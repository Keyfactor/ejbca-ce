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
package org.cesecore.util.query;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.PredicateUtils;
import org.apache.commons.lang.StringUtils;
import org.cesecore.util.QueryParameterException;
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.LogicOperator;
import org.cesecore.util.query.elems.Operation;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;

/**
 * Class responsible for Query Generation.
 * 
 * Queries will be generated according to provided Criteria. 
 * Each criteria (composing Terms) will be subdued to validation.
 * 
 * <em>For usage examples @see QueryCriteriaTest</em>
 * 
 * @version $Id$
 */
public final class QueryGenerator implements Serializable {

    private static final long serialVersionUID = 1567027442267416376L;
    private final Map<String, Object> parameters = new LinkedHashMap<>();
    private final Query query;
    private final List<String> availableFields = new ArrayList<>();
    private final QueryCriteria criteria;

    /**
     * Class holding query construction logic.
     * 
     */
    private static final class Query {
        public final StringBuilder query = new StringBuilder();
        private final String attrAlias;
        private final static String WHERE = "WHERE";
        private final static String SEPARATOR = " ";

        public Query(final String attrAlias) {
            this.attrAlias = attrAlias;
        }

        public Query where() {
            query.append(SEPARATOR).append(WHERE);
            return this;
        }

        public Query attribute(final String name) {
            query.append(SEPARATOR).append(attrAlias).append(".").append(name);
            return this;
        }

        public Query parameter(final String name) {
            query.append(SEPARATOR).append(":" + name);
            return this;
        }

        private Query operator(final RelationalOperator op) {
            final String operator = op == RelationalOperator.EQ ? "="
                    : op == RelationalOperator.GE ? ">="
                    : op == RelationalOperator.GT ? ">"
                    : op == RelationalOperator.LE ? "<="
                    : op == RelationalOperator.LT ? "<"
                    : op == RelationalOperator.NEQ ? "!="
                    : op == RelationalOperator.BETWEEN ? "BETWEEN"
                    : op == RelationalOperator.LIKE ? "LIKE"
                    : op == RelationalOperator.NULL ? "IS NULL"
                    : op == RelationalOperator.NOTNULL ? "IS NOT NULL" : "";
            if (operator.isEmpty()) {
                throw new QueryParameterException("operator not recognized");
            }
            query.append(SEPARATOR).append(operator);
            return this;
        }

        private Query operator(final LogicOperator op) {
            query.append(SEPARATOR).append(op.toString());
            return this;
        }

        public Query order(final String name, final Order.Value order) {
            query.append(SEPARATOR).append("ORDER BY").append(SEPARATOR)
                    .append(attrAlias).append(".").append(name)
                    .append(SEPARATOR).append(order.toString());
            return this;
        }

        public boolean isEmpty() {
            return query.length() == 0;
        }

        @Override
        public String toString() {
            return query.toString();
        }
    }

    private QueryGenerator(final Class<?> clazz, final QueryCriteria criteria,
            final String alias) {
        query = new Query(alias);
        this.criteria = criteria;
        for (final Field f : clazz.getDeclaredFields()) {
            availableFields.add(f.getName());
        }
    }

    /**
     * Returns a new QueryGenerator or null if criteria is null
     * @param clazz
     * @param criteria QueryCriteria
     * @param attrAlias
     * @return QueryGenerator or null if criteria is null
     */
    public static QueryGenerator generator(final Class<?> clazz,
            final QueryCriteria criteria, final String attrAlias) {
        if (criteria == null) {
            return null;
        }
        return new QueryGenerator(clazz, criteria, attrAlias);
    }

    /**
     * Generates the SQL query according to the criteria passed in generator.
     * 
     * @return generated Query.
     */
    public String generate() {
        if (query.isEmpty()) {
            final List<Elem> elements = criteria.getElements();
            final List<Elem> terms = new ArrayList<>();
            final List<Elem> clauses = new ArrayList<>();
            
            CollectionUtils.selectRejected(elements, PredicateUtils.instanceofPredicate(Order.class), terms);
            CollectionUtils.select(elements, PredicateUtils.instanceofPredicate(Order.class), clauses);
            
            if (!terms.isEmpty()) {
                query.where();
            }
            termTraversal(terms);
            clauseTraversal(clauses);
        }
        return query.toString();
    }
    
    /**
     * Traverses the terms list that is constructed according to the elements list in the QueryCriteria.
     * 
     * @param terms
     */
    private void termTraversal(List<Elem> elements) {
        boolean first = true;
        for (final Elem element : elements) {
            if (!first) {
                query.operator(LogicOperator.AND);
            } else {
                first = false;
            }
            generate(element);
        }
    }
    
    /**
     * Traverses the clauses list that is constructed according to the elements list in the QueryCriteria.
     * 
     * @param clauses
     */
    private void clauseTraversal(List<Elem> clauses) {
        for (final Elem clause : clauses) {
            generate(clause);
        }
    }

    /** 
     * Partial query generation according to the provided element.
     * 
     * @param elem Term or Operation or Order object
     */
    private void generate(final Elem elem) {
        if (elem instanceof Operation) {
            generateRestriction((Operation) elem);
        } else if (elem instanceof Term) {
            generateRestriction((Term) elem);
        } else if (elem instanceof Order) {
            generateRestriction((Order) elem);
        } else {
            throw new QueryParameterException("No matched restriction");
        }
    }

    
    private void generateRestriction(final Operation op) {
        generateRestriction(op.getTerm());
        query.operator(op.getOperator());
        final Elem elem = op.getElement();
        if (elem != null) {
            generate(elem);
        }
    }

    private void generateRestriction(final Term term) {
        validate(term.getName());
        query.attribute(term.getName()).operator(term.getOperator());
        if (term.getOperator() == RelationalOperator.BETWEEN) {
            @SuppressWarnings("unchecked")
            final AbstractMap.SimpleEntry<Object, Object> values = (AbstractMap.SimpleEntry<Object, Object>) term
                    .getValue();
            query.parameter(
                    genAndStoreParameter(term.getName(),
                            values.getKey()))
                    .operator(LogicOperator.AND)
                    .parameter(
                            genAndStoreParameter(term.getName(),
                                    values.getValue()));
        } else if (term.getOperator() != RelationalOperator.NULL
                && term.getOperator() != RelationalOperator.NOTNULL) {
            query.parameter(genAndStoreParameter(term.getName(),
                    term.getValue()));
        }
    }

    private void generateRestriction(final Order order) {
        validate(order.getName());
        query.order(order.getName(), order.getOrder());
    }

    /** @return all stored parameter names. */
    public Set<String> getParameterKeys() {
        return parameters.keySet();
    }

    /** @return the value of a stored parameter */
    public Object getParameterValue(final String key) {
        return parameters.get(key);
    }

    /**
     * Validates the provided name against our naming strategy ... columns with alphanumeric chars only.
     * 
     * @param name to be validated
     */
    private void validate(final String name) {
        if (!StringUtils.isAlphanumeric(name)) {
            throw new QueryParameterException("parameter is not alphanumeric "
                    + name);
        }
        if (!availableFields.contains(name)) {
            throw new QueryParameterException("parameter is not valid field "
                    + name);
        }
    }

    /**
     * Generated a valid parameter name. Uses an internal store to associate the generated name (parameter) to a value.
     * 
     * @param name that will be used as a seed to the parameter name
     * @param value to be associated with the parameter name
     * @return parameter name
     */
    private String genAndStoreParameter(final String name, final Object value) {
        int i = 0;
        while (true) {
            final String parameter = name + i++;
            if (!parameters.containsKey(parameter)) {
                parameters.put(parameter, value);
                return parameter;
            }

        }
    }

}

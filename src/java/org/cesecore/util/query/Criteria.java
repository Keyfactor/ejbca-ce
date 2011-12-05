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
import java.util.AbstractMap;

import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.LogicOperator;
import org.cesecore.util.query.elems.Operation;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;

/**
 * This class is a DSL sugar to all possible Criterias.
 * 
 * Based on CESeCore version: Criteria.java 1224 2011-10-17 14:06:55Z filiper 
 * 
 * @version $Id$
 */
public class Criteria implements Serializable {

    private static final long serialVersionUID = 3186042047323993627L;

    public static Elem eq(final String name, final Object value) {
        return new Term(RelationalOperator.EQ, name, value);
    }

    /** @return the query with an appended "not equal to" condition */
    public static Elem neq(final String name, final Object value) {
        return new Term(RelationalOperator.NEQ, name, value);
    }

    /** @return the query with an appended "greater than or equal to" condition */
    public static Elem geq(final String name, final Object value) {
        return new Term(RelationalOperator.GE, name, value);

    }

    /** @return the query with an appended "greater than" condition */
    public static Elem grt(final String name, final Object value) {
        return new Term(RelationalOperator.GT, name, value);

    }

    /** @return the query with an appended "less than or equal to" condition */
    public static Elem leq(final String name, final Object value) {
        return new Term(RelationalOperator.LE, name, value);

    }

    /** @return the query with an appended "less than to" condition */
    public static Elem lsr(final String name, final Object value) {
        return new Term(RelationalOperator.LT, name, value);

    }

    /** @return the query with an appended "between" condition */
    public static Elem between(final String name, final Object after,
            final Object before) {
        return new Term(RelationalOperator.BETWEEN, name,
                new  AbstractMap.SimpleEntry<Object, Object>(after, before));

    }
    
    public static Elem like(final String name, final Object value) {
        return new Term(RelationalOperator.LIKE, name, value);
    }
    
    public static Elem isNull(final String name) {
        return new Term(RelationalOperator.NULL, name, null);
    }
    
    public static Elem isNotNull(final String name) {
        return new Term(RelationalOperator.NOTNULL, name, null);
    }
    
    public static Elem and(final Elem first, final Elem second) {
        return new Operation(LogicOperator.AND, (Term)first, second);
    }
    
    public static Elem or(final Elem first, final Elem second) {
        return new Operation(LogicOperator.OR, (Term)first, second);
    }
    
    public static Elem orderAsc(final String name) {
        return new Order(name, Order.Value.ASC);
    }
        
    public static Elem orderDesc(final String name) {
        return new Order(name, Order.Value.DESC);
    }

    
}

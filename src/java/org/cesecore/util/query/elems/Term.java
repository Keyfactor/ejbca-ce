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
package org.cesecore.util.query.elems;

import org.cesecore.util.query.Elem;

/**
 * Query term. Each term is composed as followed: [name] [operator] [value] 
 * 
 * @version $Id$
 */
public final class Term implements Elem {

    private static final long serialVersionUID = 3569353821030638847L;
    private final String name;
    private final Object value;
    private final RelationalOperator operator;

    public Term(final RelationalOperator operator, final String name, final Object value) {
        this.name = name;
        this.value = value;
        this.operator = operator;
    }

    public String getName() {
        return name;
    }

    public Object getValue() {
        return value;
    }

    public RelationalOperator getOperator() {
        return operator;
    }
}

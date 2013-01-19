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
package org.cesecore.util.query.clauses;

import org.cesecore.util.query.Elem;
/**
 * Query ORDER BY element.
 * 
 * @version $Id$
 */
public class Order implements Elem {
    private static final long serialVersionUID = 4277517808022497240L;

    public enum Value {
        ASC, DESC
    }

    private final String name;
    private final Value order;

    public Order(final String name, final Value order) {
        this.name = name;
        this.order = order;
    }

    public String getName() {
        return name;
    }

    public Value getOrder() {
        return order;
    }

}

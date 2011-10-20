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
 * Operation is a combination of Terms. Terms are logiclly related by logical operators @see LogicOperator
 * 
 * Based on CESeCore version: Operation.java 1225 2011-10-17 15:44:50Z filiper
 * 
 * @version $Id$
 */
public final class Operation implements Elem {

    private static final long serialVersionUID = -4989405964837453338L;
    private final Term term;
    private final LogicOperator operator;
    private final Elem element;
    
    public Operation(final LogicOperator operator, final Term term1, final Elem element) {
        super();
        this.operator = operator;
        this.term = term1;
        this.element = element;
    }

    public Term getTerm() {
        return term;
    }

    public LogicOperator getOperator() {
        return operator;
    }
    
    public Elem getElement() {
        return element;
    }

}

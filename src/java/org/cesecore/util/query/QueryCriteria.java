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
import java.util.ArrayList;
import java.util.List;


/**
 * Query Criteria DSL.
 * 
 * This object will not contain the generated query itself. Generation and validation will be done server-side.
 * 
 * This will not guarantee that the conjunction of all restrictions will result in a good query.
 * Restrictions order should be guaranteed by the third-party lib. If not it will result in a malformed query.
 * 
 * TODO: For now there is no support for prioritizing certain conditions using parenthesis but with the current queyr generator
 * this could be easily supported.  
 * 
 * <em>For usage example @see QueryCriteriaTest</em>
 * 
 * Based on CESeCore version:
 *  QueryCriteria.java 1225 2011-10-17 15:44:50Z filiper
 * 
 * @version $Id$
 */
public final class QueryCriteria implements Serializable {
    
    private static final long serialVersionUID = 1823996498624633259L;
    private List<Elem> elements = new ArrayList<Elem>();


    private QueryCriteria() {
    }

    /** @return a new QueryCriteria */
    public static QueryCriteria create() {
        return new QueryCriteria();
    }
    
    /**
     * Adds a new Criteria (Restriction)
     * @param restriction element to be added
     * 
     * @return QueryCriteria instance for chained calls.
     */
    public QueryCriteria add(Elem elem) {
        elements.add(elem);
        return this;
    }

    public List<Elem> getElements() {
        return elements;
    }
    
}

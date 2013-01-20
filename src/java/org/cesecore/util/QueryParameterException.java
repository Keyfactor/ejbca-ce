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

/**
 * Query Criteria Exception. Thrown on entity parameter mismatch. 
 * 
 * @version $Id$
 */
public class QueryParameterException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public QueryParameterException() {
        super();
    }

    public QueryParameterException(final String arg0, final Throwable arg1) {
        super(arg0, arg1);
    }

    public QueryParameterException(final String arg0) {
        super(arg0);
    }

    public QueryParameterException(final Throwable arg0) {
        super(arg0);
    }

}

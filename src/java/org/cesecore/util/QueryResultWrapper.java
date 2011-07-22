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

import java.util.List;

import javax.persistence.NonUniqueResultException;
import javax.persistence.Query;

/**
 * Helper class to cope with Hibernates JPA 1.0 Provider implementation.
 * 
 * Based on EJBCA version: QueryResultWrapper.java 11570 2011-03-21 20:08:57Z jeklund Based on CESeCore version: QueryResultWrapper.java 933
 * 2011-07-07 18:53:11Z mikek
 * 
 * @version $Id$
 */
public abstract class QueryResultWrapper {

    /**
     * Query.getSingleResult that on with older Hibernate JPA 1.0 provider bundled with EJBCA returns null and on newer JPA implementations throws
     * NoResultException (as it should according to the specifications) is not suitable for EJBCA. We always want to return null when an object does
     * not exist, since exceptions will mess with the garbage collection and lead to worse performance.
     * 
     * We still throws NonUniqueResultException and IllegalStateException, just as getSingleResult would.
     * 
     * @return single result or null
     */
    public static <T> T getSingleResult(final Query query) {
        /*
         * The odd syntax below is due to a bug in the hotspot compiler
           See http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6302954
        */
        return QueryResultWrapper.<T> getSingleResult(query, null);
    }

    /**
     * Query.getSingleResult that on with older Hibernate JPA 1.0 provider bundled with EJBCA returns null and on newer JPA implementations throws
     * NoResultException (as it should according to the specifications) is not suitable for EJBCA. We always want to return null when an object does
     * not exist, since exceptions will mess with the garbage collection and lead to worse performance.
     * 
     * We still throws NonUniqueResultException and IllegalStateException, just as getSingleResult would.
     * 
     * @return single result or defaultValue
     */
    public static <T> T getSingleResult(final Query query, final T defaultValue) {
        @SuppressWarnings("unchecked")
        final List<T> resultList = query.getResultList();
        switch (resultList.size()) {
        case 0:
            return defaultValue;
        case 1:
            final T value = (T) resultList.get(0);
            if (value == null) {
                return defaultValue;
            } else {
                return value;
            }
        default:
            throw new NonUniqueResultException();
        }
    }

    /** @return the first result of the query or null */
    public static <T> T getLastResult(final Query query) {
        @SuppressWarnings("unchecked")
        final List<T> resultList = query.getResultList();
        switch (resultList.size()) {
        case 0:
            return null;
        default:
            return resultList.get(resultList.size() - 1);
        }
    }

}

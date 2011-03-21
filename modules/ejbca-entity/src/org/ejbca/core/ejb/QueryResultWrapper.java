/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb;

import java.util.List;

import javax.persistence.NonUniqueResultException;
import javax.persistence.Query;

/**
 * Helper class to cope with Hibernate's JPA 1.0 Provider implementation.
 * 
 * @version $Id$
 */
public abstract class QueryResultWrapper {

	/**
	 * Query.getSingleResult that on with older Hibernate JPA 1.0 provider bundled with EJBCA returns null
	 * and on newer JPA implementations throws NoResultException (as it should according to the specifications)
	 * is not suitable for EJBCA. We always want to return null when an object does not exist, since exceptions
	 * will mess with the garbage collection and lead to worse performance.
	 * 
	 * We still throws NonUniqueResultException and IllegalStateException, just as getSingleResult would.
	 * 
	 * @return single result or null
	 */
	public static Object getSingleResult(final Query query) {
		final List<Object> resultList = query.getResultList();
		switch (resultList.size()) {
		case 0:
			return null;
		case 1:
			return resultList.get(0);
		default:
			throw new NonUniqueResultException();
		}
	}

	/** @return the first result of the query or null */
	public static Object getLastResult(final Query query) {
		final List<Object> resultList = query.getResultList();
		switch (resultList.size()) {
		case 0:
			return null;
		default:
			return resultList.get(resultList.size()-1);
		}
	}
}

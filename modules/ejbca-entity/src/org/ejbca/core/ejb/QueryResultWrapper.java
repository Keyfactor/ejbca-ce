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

import javax.persistence.NoResultException;
import javax.persistence.Query;

/**
 * Helper class to cope with Hibernates JPA 1.0 Provider implementation.
 * 
 * @version $Id$
 */
public abstract class QueryResultWrapper {

	/**
	 * The older Hibernate JPA 1.0 provider bundled with EJBCA returns null instead of throwing
	 * the NoResultException it should according to the specifications. This is corrected in later
	 * versions, but we need to function with both.
	 * 
	 * Still throws NonUniqueResultException and IllegalStateException.
	 * 
	 * @return query.getSingleResult() or null
	 */
	public static Object getResultAndSwallowNoResultException(Query query) {
		Object ret = null;
		try {
			ret = query.getSingleResult();
		} catch (NoResultException e) {
		}
		return ret;
	}
}

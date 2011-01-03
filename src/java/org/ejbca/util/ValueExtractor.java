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

package org.ejbca.util;

/**
 * Helper object to convert from JDBC driver specific objects to a unified form. 
 *
 * @version $Id$
 */
public abstract class ValueExtractor {

	/**
	 * Return the intValue if the supplied object has a "intValue" method.
	 * Since different JDBC driver will return different types of objects like
	 * Integer, BigInteger or BigDecimal (Oracle) this is convenient.
	 */
	public static int extractIntValue(Object object) {
		try {
			return ((Integer) object.getClass().getMethod("intValue").invoke(object)).intValue();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Return the longValue if the supplied object has a "longValue" method.
	 * Since different JDBC driver will return different types of objects like
	 * Long, BigInteger or BigDecimal (Oracle) this is convenient.
	 */
	public static long extractLongValue(Object object) {
		try {
			return ((Long) object.getClass().getMethod("longValue").invoke(object)).longValue();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}

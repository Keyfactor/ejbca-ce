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

import org.apache.log4j.Logger;

/**
 * Helper object to convert from JDBC driver specific objects to a unified form. 
 *
 * @version $Id$
 */
public abstract class ValueExtractor {
	
	private static final Logger LOG = Logger.getLogger(ValueExtractor.class);
	private static final String ERRMSG_NOTONE = "Array of values with not exactly one value! Using first field.";

	/**
	 * Return the intValue if the supplied object has a "intValue" method.
	 * Since different JDBC driver will return different types of objects like
	 * Integer, BigInteger or BigDecimal (Oracle) this is convenient.
	 */
	public static int extractIntValue(Object object) {
		Class<?> c = object.getClass();
		try {
			if (c.isArray()) {
				final Object[] objects = (Object[]) object;
				if (objects.length != 1) {
					LOG.warn(ERRMSG_NOTONE);
				}
				c = objects[0].getClass();
			}
			return ((Integer) c.getMethod("intValue").invoke(object)).intValue();
		} catch (NoSuchMethodException e) {
			LOG.error(c.getName() + ", isPrimitive=" + c.isPrimitive(), e);
			throw new RuntimeException(e);
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
		Class<?> c = object.getClass();
		try {
			if (c.isArray()) {
				final Object[] objects = (Object[]) object;
				if (objects.length != 1) {
					LOG.warn(ERRMSG_NOTONE);
				}
				c = objects[0].getClass();
			}
			return ((Long) c.getMethod("longValue").invoke(object)).longValue();
		} catch (NoSuchMethodException e) {
			LOG.error(object.getClass().getName() + ", isPrimitive=" + object.getClass().isPrimitive(), e);
			throw new RuntimeException(e);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}

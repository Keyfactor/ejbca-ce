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

import java.math.BigDecimal;
import java.math.BigInteger;

import org.apache.log4j.Logger;

/**
 * Helper object to convert from JDBC driver specific objects to a unified form. 
 *
 * Based on ValueExtractor.java 207 2011-01-31 13:36:36Z tomas from cesecore
 * 
 * @version $Id$
 */
public abstract class ValueExtractor {
	
	private static final Logger LOG = Logger.getLogger(ValueExtractor.class);

	/**
	 * Return the intValue if the supplied object has a "intValue" method.
	 * Since different JDBC driver will return different types of objects like
	 * Integer, BigInteger or BigDecimal (Oracle) this is convenient.
	 * 
	 * As a sad little bonus, DB2 native queries returns a pair of {BigInteger, Integer}
	 * where the first value is row and the second is the value.
	 * As another sad little bonus, Oracle native queries returns a pair of {BigDecimal, BigDecimal}
	 * where the first value is the value and the second is the row.
	 */
	public static int extractIntValue(Object object) {
		Class<?> c = object.getClass();
		try {
            c = getClass(object, Integer.class);
			return ((Integer) c.getMethod("intValue").invoke(object)).intValue();
		} catch (Exception e) {
			LOG.error(c.getName() + ", isPrimitive=" + c.isPrimitive(), e);
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
		    c = getClass(object, Long.class);
			return ((Long) c.getMethod("longValue").invoke(object)).longValue();
		} catch (Exception e) {
			LOG.error(c.getName() + ", isPrimitive=" + c.isPrimitive(), e);
			throw new RuntimeException(e);
		}
	}
	
	/** 
	 * 
	 * @param object will be changed if it is an array type object
	 * @param clazz only used for logging
	 * @return Class of the object to get value from
	 */
	private static Class<?> getClass(Object object, final Class<?> clazz) {
        Class<?> c = object.getClass();
        if (c.isArray()) {
            final Object[] objects = (Object[]) object;
            if (LOG.isTraceEnabled()) {
                for (Object o : objects) {
                    LOG.trace(o.getClass().getName() + " isPrimitive=" + o.getClass().isPrimitive() + " toString=" + o.toString());
                }
            }
            if (objects[0].getClass().equals(BigInteger.class)) {
                object = objects[objects.length-1];
            } else if (objects[objects.length-1].getClass().equals(BigDecimal.class)) {
                object = objects[0];
            } else {
                throw new RuntimeException("Unsupported object type to cenvert to "+clazz.getSimpleName());
            }
            c = object.getClass();
        }
        return c;
	}
}

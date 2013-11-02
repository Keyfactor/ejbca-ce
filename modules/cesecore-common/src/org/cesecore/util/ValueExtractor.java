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
        try {
            final Object o = getObject(object, Integer.class);
            final Class<?> c = o.getClass();
            return ((Integer) c.getMethod("intValue").invoke(o)).intValue();
        } catch (Exception e) {
            final Class<?> c = object.getClass();
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
        try {
            final Object o = getObject(object, Long.class);
            final Class<?> c = o.getClass();
            return ((Long) c.getMethod("longValue").invoke(o)).longValue();
        } catch (Exception e) {
            final Class<?> c = object.getClass();
            LOG.error(c.getName() + ", isPrimitive=" + c.isPrimitive(), e);
            throw new RuntimeException(e);
        }
    }
    
       /** 
     * 
     * @param object to check if it is an array type and in that case extract the BigInteger, BigDecimal or Integer object
     * @param clazz only used for logging
     * @return the object to get value from
     */
    private static Object getObject(final Object object, final Class<?> clazz) {
        Object ret = object;
        final Class<?> c = object.getClass();
        if (c.isArray()) {
            final Object[] objects = (Object[]) object;
            if (LOG.isTraceEnabled()) {
                for (Object o : objects) {
                    LOG.trace(o.getClass().getName() + " isPrimitive=" + o.getClass().isPrimitive() + " toString=" + o.toString());
                }
            }
            if (objects[0].getClass().equals(BigInteger.class)) {
                // DB2 native queries returns a pair of {BigInteger, Integer} where the first value is row and the second is the value.
                ret = objects[objects.length-1];
            } else if (objects[objects.length-1].getClass().equals(BigDecimal.class)) {
                // Oracle native queries returns a pair of {BigDecimal, BigDecimal} where the first value is the value and the second is the row
                ret = objects[0];
            } else if (objects[0].getClass().equals(Integer.class)) {
                // Yet another variant (DB2 again) returns a pair of {Integer, BigInteger} where the first value is the value and the second is the row.
                ret = objects[0];
            } else {
                if (objects.length > 1) {
                    throw new RuntimeException("Unsupported object type to convert to "+clazz.getSimpleName() + ". Was: objects.length="+objects.length+", objects[0] is a "+objects[0].getClass().getName()+": "+objects[0]+", objects[1] is a "+objects[1].getClass().getName()+": "+objects[1]);                    
                } else {
                    throw new RuntimeException("Unsupported object type to convert to "+clazz.getSimpleName() + ". Was: objects.length="+objects.length+", objects[0] is a "+objects[0].getClass().getName()+": "+objects[0]);                    
                }
            }
        }
        return ret;
    }

}

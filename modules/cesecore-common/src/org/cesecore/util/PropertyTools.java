/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import org.apache.commons.lang3.StringUtils;

import java.util.Properties;

/**
 * Utility methods for Properties objects.
 */
public final class PropertyTools {

    private PropertyTools() {}

    public static boolean get(final Properties properties, final String propertyName, final boolean defaultValue) {
        final String value = properties.getProperty(propertyName);
        return StringUtils.isNotEmpty(value) ? Boolean.parseBoolean(value) : defaultValue;
    }
    
    public static int get(final Properties properties, final String propertyName, final int defaultValue) {
        final String value = properties.getProperty(propertyName);
        return StringUtils.isNotEmpty(value) ? Integer.parseInt(value) : defaultValue;
    }
    
    public static long get(final Properties properties, final String propertyName, final long defaultValue) {
        final String value = properties.getProperty(propertyName);
        return StringUtils.isNotEmpty(value) ? Long.parseLong(value) : defaultValue;
    }

}

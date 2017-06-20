/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.ca.keys.validation;

import java.util.List;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;

/**
 * Static helper class for custom UI properties.
 * 
 * @version $Id: CustomKeyValidatorTools.java 22117 2017-04-01 12:12:00Z anjakobs $
 */
public class CustomKeyValidatorTools {

    /** Class logger. */
    private static final Logger LOG = Logger.getLogger(CustomKeyValidatorTools.class);

    /** Text literal for '='. */
    private static final char EQUALS = '=';
    
    /** Text literal for ';'. */
    private static final String LIST_SEPARATOR = ";";
    
    
    /**
     * Gets a java.util.Properties object by the string.
     * @param string the serialized custom properties string.
     * @return the properties.
     */
    public static final Properties getProperties(final String string) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Transform custom properties string " + string);
        }
        final Properties result = new Properties();
        if (StringUtils.isNotBlank(string)) {
            final String[] pairs = string.split(LIST_SEPARATOR);
            int index;
            for (String pair : pairs) {
                if ((index = pair.indexOf(EQUALS)) > -1) {
                    result.setProperty(pair.substring(0, index), pair.substring(index + 1));
                }
            }
        }
        return result;
    }

    /**
     * Creates a serialization string by the given custom properties.
     * @param properties the list of custom properties.
     * @return the properties string.
     */
    public static final String getString(final List<CustomKeyValidatorProperty> properties) {
        final StringBuilder builder = new StringBuilder();
        for (CustomKeyValidatorProperty property : properties) {
            if (builder.length() > 0) {
                builder.append(LIST_SEPARATOR);
            }
            if (property.getType() == CustomPublisherProperty.UI_BOOLEAN) {
                if (StringUtils.isBlank(property.getValue()) || Boolean.FALSE.toString().equals(property.getValue())) {
                    builder.append(property.getName()).append(EQUALS).append(Boolean.FALSE.toString());
                } else {
                    builder.append(property.getName()).append(EQUALS).append(Boolean.TRUE.toString());
                }
            } else {
                builder.append(property.getName()).append(EQUALS).append(property.getValue());
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Transform custom properties object " + builder.toString());
        }
        return builder.toString();
    }

    /**
     * Avoid instantiation.
     */
    private CustomKeyValidatorTools() {
    }
}

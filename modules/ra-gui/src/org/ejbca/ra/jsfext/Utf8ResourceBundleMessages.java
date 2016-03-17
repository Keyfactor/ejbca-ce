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
package org.ejbca.ra.jsfext;

import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import javax.faces.context.FacesContext;

/**
 * Special handling for our resource bundles, so we can store messages keys as UTF-8.
 * 
 * @version $Id$
 */
public class Utf8ResourceBundleMessages extends ResourceBundle {

    private final static String RESOURCE_BUNDLE_BASENAME = "Messages";
    private final ResourceBundle fallBackResourceBundle;
    
	public Utf8ResourceBundleMessages() {
	    final Locale currentLocale = FacesContext.getCurrentInstance().getViewRoot().getLocale();
        final Locale defaultLocale = FacesContext.getCurrentInstance().getApplication().getDefaultLocale();
        super.setParent(ResourceBundle.getBundle(RESOURCE_BUNDLE_BASENAME, currentLocale));
	    if (currentLocale.equals(defaultLocale)) {
	        fallBackResourceBundle = null;
	    } else {
	        fallBackResourceBundle = ResourceBundle.getBundle(RESOURCE_BUNDLE_BASENAME, defaultLocale);
	    }
    }

    @Override
    protected Object handleGetObject(String key) {
        Object value;
        try {
            value = parent.getObject(key);
        } catch (MissingResourceException e) {
            if (fallBackResourceBundle==null) {
                throw e;
            }
            value = fallBackResourceBundle.getObject(key);
        }
        if (value instanceof String) {
        	/*
        	 *  The resource String is actually stored as UTF-8, but the PropertyResourceBundle has read it using
        	 *  ISO_8859_1, so we need to reinterpret it with the correct encoding.
        	 */
            return new String(((String)value).getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
        }
        return value;
    }

    @Override
    public Enumeration<String> getKeys() {
        if (fallBackResourceBundle==null) {
            return parent.getKeys();
        }
        return fallBackResourceBundle.getKeys();
    }
}

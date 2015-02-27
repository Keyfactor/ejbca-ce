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
package org.ejbca.ui.web.admin;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

import org.ejbca.config.WebConfiguration;

/**
 * Class with utility methods to find all implementations of a given
 * interface using the ServiceLoader functionality of JRE 1.6.
 *
 * @version $Id$
 */
public class CustomLoader {

    private CustomLoader() { }

    /**
     * Searches for all implementations of a given interface using
     * java.util.ServiceLoader. The implementations class names must
     * be added to the text file META-INF/services/ in its JAR file,
     * with one class name per line.
     * 
     * @return A list of class names (including the full package paths)
     */
    public static <T> List<String> getCustomClasses(Class<T> interfaceClass) {
        List<String> classes = new ArrayList<String>();
        ServiceLoader<T> svcloader = ServiceLoader.load(interfaceClass);
        for (T implInstance : svcloader) {
            String name = implInstance.getClass().getName();
            classes.add(name);
        }
        return classes;
    }

    /**
     * Checks whether a class was displayed in the list of classes in the user interface.
     */
    public static boolean isDisplayedInList(String className, Class<?> interfaceClass) {
        if (!WebConfiguration.isManualClassPathsEnabled()) return true; // otherwise old manual classes won't be shown in the GUI
        return getCustomClasses(interfaceClass).contains(className);
    }

}

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
package org.ejbca.ui.web.admin;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Class with utility methods to find all implementations of a given
 * interface using the ServiceLoader functionality of JRE 1.6.
 * 
 * @author Samuel Lidén Borell
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
     * Checks if the given class is present in the list of auto-detected
     * classes from the getCustomClasses method. 
     */
    public static boolean isAutoClass(String className, Class<?> interfaceClass) {
        return getCustomClasses(interfaceClass).contains(className);
    }

}

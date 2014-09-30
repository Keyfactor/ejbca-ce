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
package org.ejbca;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * @version $Id$
 *
 */
public class ServiceLocatorTestUtils {

    /**
     * Add the given directory to the classpath, and create a service manifest there for the given interface,
     * specifying the given members. 
     * 
     * Code heavily borrowed from SeviceManifestBuilder, but we don't want to create a dependency to it.
     * 
     * @param directory
     * @param interfaceClass
     * @param implementingClasses
     */
    public static void createServiceManifest(File directory, Class<?> interfaceClass, Class<?>... implementingClasses) {
        if (!interfaceClass.isInterface()) {
            throw new RuntimeException(interfaceClass.getSimpleName() + " is not an interface.");
        }
        for (Class<?> member : implementingClasses) {
            if (!interfaceClass.isAssignableFrom(member)) {
                throw new RuntimeException(member.getName() + " does not implement " + interfaceClass.getSimpleName());
            }
            if (Modifier.isAbstract(member.getModifiers())) {
                throw new RuntimeException(member.getSimpleName() + " was abstract.");
            }
        }
        if (!directory.isDirectory()) {
            throw new RuntimeException(directory.getAbsolutePath() + " was not a directory.");
        }
        //Add directory to classpath
        URLClassLoader sysloader = (URLClassLoader) ClassLoader.getSystemClassLoader();
        try {
            Method method = URLClassLoader.class.getDeclaredMethod("addURL", new Class[] { URL.class });
            method.setAccessible(true);
            method.invoke(sysloader, new Object[] { directory.toURI().toURL() });
        } catch (Throwable t) {
            throw new RuntimeException("Exception caught while trying to haxxor classpath", t);
        }
        File metaInf = new File(directory, "META-INF");
        if (!metaInf.exists()) {
            if (!metaInf.mkdir()) {
                throw new RuntimeException("Could not create META-INF directory.");
            }
        }
        File services = new File(metaInf, "Services");
        if (!services.exists()) {
            if (!services.mkdir()) {
                throw new RuntimeException("Could not create Services directory.");
            }
        }
        final File manifestFile = new File(services, interfaceClass.getName());
        try {
            if (!manifestFile.exists()) {
                if (!manifestFile.createNewFile()) {
                    throw new RuntimeException("Could not create manifest file.");
                }
            }
            PrintWriter printWriter = new PrintWriter(manifestFile);
            try {
                for (Class<?> implementingClass : implementingClasses) {
                    printWriter.println(implementingClass.getName());
                }
            } finally {
                printWriter.flush();
                printWriter.close();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

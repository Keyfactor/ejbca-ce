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
package org.ejbca.core.model.era;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test to verify implementation constraints of RaMasterApi.
 * 
 * Verifies that:
 * - all defined classes are Serializable
 * - method names are unique
 * 
 * @version $Id$
 */
public class RaMasterApiTest {
    
    private static final Logger log = Logger.getLogger(RaMasterApiTest.class);

    @Test
    public void testUniqueMethodNames() {
        final Set<String> methodNames = new HashSet<>();
        for (final Method method : RaMasterApi.class.getDeclaredMethods()) {
            assertTrue("Design violation. Non-unique method name " + method.getName() + " detected.", methodNames.add(method.getName()));
        }
    }

    @Test
    public void testSerializable() {
        final Set<Class<?>> referencedClasses = getReferencedClassesInInterface(RaMasterApi.class);
        final Set<Class<?>> allReferencedClasses = new HashSet<>(referencedClasses);
        int size = 0;
        while (size<allReferencedClasses.size()) {
            size = allReferencedClasses.size();
            for (final Class<?> clazz : new HashSet<>(allReferencedClasses)) {
                allReferencedClasses.addAll(getReferencedClasses(clazz));
            }
        }
        List<String> violators = new ArrayList<>();
        List<String> violatorsInInterface = new ArrayList<>();
        for (final Class<?> clazz : allReferencedClasses) {
            if (!clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers()) && !Serializable.class.isAssignableFrom(clazz)) {
                violators.add(clazz.getName());
                if (referencedClasses.contains(clazz)) {
                    violatorsInInterface.add(clazz.getName());
                }
            }
        }
        Collections.sort(violators);
        Collections.sort(violatorsInInterface);
        final StringBuilder sb = new StringBuilder();
        if (violatorsInInterface.isEmpty()) {
            for (final String className : violators) {
                log.debug(" " + className + " matched violation rule.");
                if (sb.length()>0) {
                    sb.append(", ");
                }
                sb.append(className);
            }
        } else {
            // No need to show every referenced violation if there is a clear source of this
            for (final String className : violatorsInInterface) {
                log.debug(" " + className + " matched violationInterface rule.");
                if (sb.length()>0) {
                    sb.append(", ");
                }
                sb.append(className);
            }
        }
        assertEquals("Design violation. The following referenced classes of RaMasterApi are not Serializable: " + sb.toString(), 0, sb.length());
    }

    /** @return a Set of all classes declared as method parameters, method return types, method Exceptions in the specified interface */
    private Set<Class<?>> getReferencedClassesInInterface(final Class<?> clazz) throws NoClassDefFoundError {
        final Set<Class<?>> acceptedClasses = new HashSet<>();
        for (final Method method : clazz.getDeclaredMethods()) {
            final Class<?>[] methodParamClasses = method.getParameterTypes();
            for (final Class<?> c : methodParamClasses) {
                acceptedClasses.add(c);
            }
            final Class<?>[] methodExceptionClasses = method.getExceptionTypes();
            for (final Class<?> c : methodExceptionClasses) {
                acceptedClasses.add(c);
            }
            acceptedClasses.add(method.getReturnType());
        }
        return acceptedClasses;
    }

    /** @return a Set of all classes declared as non-transient, non-static field in the class */
    private Set<Class<?>> getReferencedClasses(final Class<?> clazz) throws NoClassDefFoundError {
        final Set<Class<?>> acceptedClasses = new HashSet<>();
        for (final Field field : clazz.getDeclaredFields()) {
            if (!Modifier.isStatic(field.getModifiers()) && !Modifier.isTransient(field.getModifiers())) {
                acceptedClasses.add(field.getDeclaringClass());
            }
        }
        final Class<?> superClass = clazz.getSuperclass();
        if (superClass!=null) {
            acceptedClasses.addAll(getReferencedClasses(superClass));
        }
        return acceptedClasses;
    }
}

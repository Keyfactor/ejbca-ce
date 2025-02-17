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
package org.ejbca.ui.web;

import java.io.IOException;
import java.util.Collection;
import java.util.TreeSet;

import com.google.common.reflect.ClassPath;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.view.ViewScoped;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class SessionAndViewScopedBeansAreSerializableUnitTest {
    private Class<?> aSerializableClass;

    @Parameters(name = "{0}")
    public static Collection<Class<?>> getViewAndSessionScopedBeans() throws IOException {
        // find all session and view scoped beans
        var beans = new TreeSet<Class<?>>((c1, c2) -> c1.getName().compareTo(c2.getName()));
        ClassPath.from(SessionAndViewScopedBeansAreSerializableUnitTest.class.getClassLoader()).getAllClasses().forEach(c -> {
            if (SerializationUtils.isOurClass(c)) {
                // dont worry about unit tests
                if (!c.getName().contains("UnitTest")) {
                    Class<?> ejbcaClass = c.load();
                    if (ejbcaClass.getAnnotation(SessionScoped.class) != null || ejbcaClass.getAnnotation(ViewScoped.class) != null) {
                        beans.add(ejbcaClass);
                    }
                }
            }
        });

        return beans;
    }

    public SessionAndViewScopedBeansAreSerializableUnitTest(Class<?> aSerializableClass) {
        this.aSerializableClass = aSerializableClass;
    }

    /**
     * For EJBCA to work in an HA environment, all members of View or Session scoped beans must be serializable.
     * In HA mode, the state of these beans are serialized to a session store and de-serialized on other nodes 
     * in a load balanced environment.
     * 
     * In general, this means that you should ensure that any fields are classes that implement Serializable.
     * If that's not possible, then you can often mark the field as `transient`.  
     * 
     * {@link AuthenticationToken} and classes that contain AuthenticationTokens are a special case - they 
     * are explicitly forbidden from being serialized and then de-serialized on another JVM.  To create
     * an AuthenticationToken field, it is best to mark it as `transient` and create a lazy-constructing
     * "getter" and only use that method to access the field.
     */
    @Test
    public void allMembersAreSerializable() throws Exception {
        // go through all our beans and ensure that all their fields are serializable
        assertTrue(aSerializableClass.toString() + " is a bean and should be serializable", SerializationUtils.isSerializable(aSerializableClass));
        //@formatter:off
        SerializationUtils.findFirstUnserializableMember(aSerializableClass).ifPresent(
                fieldAndClass -> fail(
                        aSerializableClass 
                        + " contains a field " + fieldAndClass.getLeft().getName()
                        + " with class " + fieldAndClass.getRight().getCanonicalName() 
                        + " which is not serializable"));
        //@formatter:on
    }
}

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

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.TreeSet;


import com.google.common.reflect.ClassPath;

import org.apache.commons.lang3.ClassUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.endentity.SubjectDnFieldData;
import org.junit.Test;

import jakarta.ejb.EJB;
import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.annotation.ManagedProperty;
import jakarta.faces.view.ViewScoped;

import static org.junit.Assert.*;

public class SerializableClassesAreCorrectUnitTest {

    private static boolean isSerializable(Class<?> clazz) {
        if (clazz.isPrimitive())
            return true;
        else if (clazz.isEnum())
            return true;
        else if (clazz.isArray())
            return isSerializable(clazz.getComponentType());

        // these classes are marked as serializable, but it really aren't.
        // Generally bacause they contain AuthenticationTokens
        else if (clazz.isAssignableFrom(CAInterfaceBean.class))
            return false;
        else if (clazz.isAssignableFrom(AuthenticationToken.class))
            return false;

        boolean isSerializable = false;
        for (var iface : ClassUtils.getAllInterfaces(clazz)) {
            if (iface.isAssignableFrom(Serializable.class)) {
                isSerializable = true;
            }
        }
        return isSerializable;
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
    public void allSessionAndViewScopedBeansAreSerializable() throws Exception {
        // find all session and view scoped beans
        var beans = new TreeSet<Class<?>>((c1, c2) -> c1.getName().compareTo(c2.getName()));
        ClassPath.from(getClass().getClassLoader()).getAllClasses().forEach(c -> {
            if (c.getPackageName().startsWith("org.ejbca") || c.getPackageName().startsWith("org.cesecore")) {
                // dont worry about unit tests
                if (!c.getName().contains("UnitTest")) {
                    Class<?> ejbcaClass = c.load();
                    if (ejbcaClass.getAnnotation(SessionScoped.class) != null || ejbcaClass.getAnnotation(ViewScoped.class) != null) {
                        beans.add(ejbcaClass);
                    }
                }
            }
        });

        // go through all our beans and ensure that all their fields are serializable
        for (Class<?> clazz : beans) {
            assertTrue(clazz.toString() + " is a bean and should be serializable", isSerializable(clazz));
            classIsSerializable(clazz);
        }
    }

    /**
     * Any class that implements Serializable should have all members be serializable or transient.  Or possibly
     * a custom readObject() method - in 
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
    public void allSerializableClassesAreSerializable() throws Exception {
        // find all session and view scoped beans
        var beans = new TreeSet<Class<?>>((c1, c2) -> c1.getName().compareTo(c2.getName()));
        ClassPath.from(getClass().getClassLoader()).getAllClasses().forEach(c -> {
            if (c.getPackageName().startsWith("org.ejbca") || c.getPackageName().startsWith("org.cesecore")) {
                // dont worry about unit tests
                if (!c.getName().contains("UnitTest")) {
                    Class<?> ejbcaClass = c.load();
                    if (ejbcaClass.isAssignableFrom(Serializable.class))
                        beans.add(ejbcaClass);
                }
            }
        });

        // go through all our beans and ensure that all their fields are serializable
        for (Class<?> clazz : beans) {
            classIsSerializable(clazz);
        }
    }

    @Test
    public void canSerializeSubjectDnFieldData() throws Exception {
        try {
            new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(new SubjectDnFieldData.Builder("abc", false, false).build());
        } catch (NotSerializableException e) {
            fail(e.toString());
        }
    }

    private void classIsSerializable(Class<?> clazz) {
        for (Field field : clazz.getDeclaredFields()) {
            // skip static, transient and dependency injected fields
            if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers()))
                continue;
            if (field.isAnnotationPresent(EJB.class))
                continue;
            if (field.isAnnotationPresent(ManagedProperty.class))
                continue;

            // for collection types, check their contained type
            Class<?> type = field.getType();
            if (java.util.Map.class.isAssignableFrom(type) || java.util.Set.class.isAssignableFrom(type)
                    || java.util.List.class.isAssignableFrom(type) || java.util.Collection.class.isAssignableFrom(type)) {
                type = field.getGenericType().getClass();
                continue;
            }

            java.awt.datatransfer.StringSelection classNameSelection = new java.awt.datatransfer.StringSelection(clazz.getCanonicalName());
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(classNameSelection, classNameSelection);
            assertTrue(clazz + " contains a field " + field.getName() + " with class " + type.getCanonicalName() + " which is not serializable",
                    isSerializable(type));
        }
    }
}
